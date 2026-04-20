import inspect
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from PyQt6.QtCore import QObject, QProcess, QRunnable, QThreadPool, pyqtSignal

from .utils import core_executable_path


@dataclass
class SessionResult:
    request_id: str
    exit_code: int = 0
    phase: str = ""
    message: str = ""
    all_lines: list[str] = field(default_factory=list)
    result_lines: list[str] = field(default_factory=list)
    result_path: str | None = None
    metadata: dict[str, Any] | None = None
    result_payload: Any = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessResult:
    command: list[str]
    exit_code: int
    all_lines: list[str] = field(default_factory=list)
    stdout_lines: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)


class _CallableSignals(QObject):
    success = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(object)
    finished = pyqtSignal()


class _CallableTask(QRunnable):
    def __init__(self, fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any] | None = None):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs or {}
        self.signals = _CallableSignals()
        self.setAutoDelete(True)

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:
            self.signals.error.emit(str(exc))
        else:
            self.signals.success.emit(result)
        finally:
            self.signals.finished.emit()


class BackendSessionClient(QObject):
    """维护一个常驻的 C++ 后端会话，并通过 JSON 行协议收发消息。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        self._pending_requests: dict[str, dict[str, Any]] = {}
        self._dataset_signature: tuple[str, int, int] | None = None
        self._dataset_metadata: dict[str, Any] | None = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning

    def active_request_ids(self) -> list[str]:
        return list(self._pending_requests)

    def restart(self):
        self.close()

    def close(self):
        if self._process is None:
            self._dataset_signature = None
            self._dataset_metadata = None
            return

        process = self._process
        self._process = None
        try:
            process.readyReadStandardOutput.disconnect()
        except TypeError:
            pass
        try:
            process.readyReadStandardError.disconnect()
        except TypeError:
            pass
        try:
            process.finished.disconnect()
        except TypeError:
            pass

        if process.state() != QProcess.ProcessState.NotRunning:
            try:
                payload = {"request_id": uuid.uuid4().hex, "action": "shutdown"}
                process.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
                process.waitForBytesWritten(500)
                process.waitForFinished(1000)
            except Exception:
                process.kill()
                process.waitForFinished(1000)

        process.deleteLater()
        self._fail_all_pending("后端会话已关闭")
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        self._dataset_signature = None
        self._dataset_metadata = None

    def load_dataset(
        self,
        input_file: str,
        threads: int,
        *,
        on_output: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_success: Callable[[SessionResult], None] | None = None,
        on_finished: Callable[[SessionResult], None] | None = None,
    ) -> str | None:
        try:
            signature = (os.path.abspath(input_file), int(os.path.getmtime(input_file)), int(threads))
        except OSError:
            signature = (os.path.abspath(input_file), 0, int(threads))

        if self._dataset_signature == signature and self._dataset_metadata and self.is_running():
            result = SessionResult(
                request_id="reused",
                phase="index_warmup",
                message="复用已加载图模型",
                all_lines=["复用已加载图模型"],
                metadata=self._dataset_metadata,
                raw={"metadata": self._dataset_metadata},
            )
            if on_output is not None:
                on_output("复用已加载图模型")
            if on_success is not None:
                on_success(result)
            if on_finished is not None:
                on_finished(result)
            return None

        self.restart()
        request_id = self._send_request(
            {
                "action": "load_dataset",
                "input_file": input_file,
                "threads": threads,
            },
            on_output=on_output,
            on_error=on_error,
            on_success=on_success,
            on_finished=on_finished,
        )
        if request_id is not None:
            self._pending_requests[request_id]["load_signature"] = signature
        return request_id

    def run_task(
        self,
        payload: dict[str, Any],
        *,
        on_output: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_success: Callable[[SessionResult], None] | None = None,
        on_finished: Callable[[SessionResult], None] | None = None,
    ) -> str | None:
        request = dict(payload)
        request["action"] = request.get("action", "run_task")
        return self._send_request(
            request,
            on_output=on_output,
            on_error=on_error,
            on_success=on_success,
            on_finished=on_finished,
        )

    def request_status(
        self,
        *,
        on_success: Callable[[SessionResult], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> str | None:
        return self._send_request(
            {"action": "get_status"},
            on_success=on_success,
            on_error=on_error,
        )

    def _ensure_process(self) -> QProcess:
        if self.is_running():
            return self._process

        process = QProcess(self)
        self._process = process
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        executable = core_executable_path()
        process.setProgram(executable)
        process.setArguments(["--session"])
        process.setWorkingDirectory(os.path.dirname(executable))
        process.readyReadStandardOutput.connect(self._handle_stdout)
        process.readyReadStandardError.connect(self._handle_stderr)
        process.finished.connect(self._handle_finished)
        process.start()

        if not process.waitForStarted(5000):
            error = f"启动后端会话失败: {process.errorString()}"
            self._process = None
            process.deleteLater()
            raise RuntimeError(error)
        return process

    def _send_request(
        self,
        payload: dict[str, Any],
        *,
        on_output: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_success: Callable[[SessionResult], None] | None = None,
        on_finished: Callable[[SessionResult], None] | None = None,
    ) -> str | None:
        if self._pending_requests:
            active = next(iter(self._pending_requests))
            message = f"后端忙碌中，请等待当前任务完成: {active}"
            if on_error is not None:
                on_error(message)
            return None

        request_id = uuid.uuid4().hex
        payload = dict(payload)
        payload["request_id"] = request_id
        process = self._ensure_process()
        self._pending_requests[request_id] = {
            "on_output": on_output,
            "on_error": on_error,
            "on_success": on_success,
            "on_finished": on_finished,
            "all_lines": [],
            "progress_lines": [],
            "payload": payload,
        }
        encoded = json.dumps(payload, ensure_ascii=False) + "\n"
        process.write(encoded.encode("utf-8"))
        if not process.waitForBytesWritten(3000):
            self._fail_request(request_id, "向后端发送请求失败")
            return None
        return request_id

    def _handle_stdout(self):
        if self._process is None:
            return
        chunk = bytes(self._process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self._stdout_buffer += chunk
        while "\n" in self._stdout_buffer:
            line, self._stdout_buffer = self._stdout_buffer.split("\n", 1)
            line = line.rstrip("\r").strip()
            if not line:
                continue
            self._dispatch_stdout_line(line)

    def _handle_stderr(self):
        if self._process is None:
            return
        chunk = bytes(self._process.readAllStandardError()).decode("utf-8", errors="replace")
        self._stderr_buffer += chunk
        while "\n" in self._stderr_buffer:
            line, self._stderr_buffer = self._stderr_buffer.split("\n", 1)
            line = line.rstrip("\r").strip()
            if not line:
                continue
            if self._pending_requests:
                request_id = next(iter(self._pending_requests))
                callbacks = self._pending_requests[request_id]
                callbacks["all_lines"].append(line)
                if callbacks["on_error"] is not None:
                    callbacks["on_error"](line)

    def _dispatch_stdout_line(self, line: str):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            if self._pending_requests:
                request_id = next(iter(self._pending_requests))
                callbacks = self._pending_requests[request_id]
                callbacks["all_lines"].append(line)
                if callbacks["on_output"] is not None:
                    callbacks["on_output"](line)
            return

        request_id = payload.get("request_id")
        if not request_id or request_id not in self._pending_requests:
            return

        callbacks = self._pending_requests[request_id]
        event = payload.get("event")
        message = str(payload.get("message") or "").strip()

        if event == "progress":
            if message:
                callbacks["progress_lines"].append(message)
                callbacks["all_lines"].append(message)
                if callbacks["on_output"] is not None:
                    callbacks["on_output"](message)
            return

        if event == "error":
            error_message = str(payload.get("error") or message or "后端任务失败")
            self._fail_request(request_id, error_message)
            return

        if event != "complete":
            return

        result_lines = [str(item) for item in payload.get("result_lines") or []]
        for result_line in result_lines:
            callbacks["all_lines"].append(result_line)
            if callbacks["on_output"] is not None:
                callbacks["on_output"](result_line)

        result = SessionResult(
            request_id=request_id,
            phase=str(payload.get("phase") or ""),
            message=message,
            all_lines=list(callbacks["all_lines"]),
            result_lines=result_lines,
            result_path=payload.get("result_path") or None,
            metadata=payload.get("metadata"),
            result_payload=payload.get("result_payload"),
            raw=payload,
        )

        load_signature = callbacks.get("load_signature")
        if load_signature and result.metadata is not None:
            self._dataset_signature = load_signature
            self._dataset_metadata = result.metadata

        on_success = callbacks.get("on_success")
        on_finished = callbacks.get("on_finished")
        del self._pending_requests[request_id]
        if on_success is not None:
            on_success(result)
        if on_finished is not None:
            on_finished(result)

    def _handle_finished(self, exit_code: int, _exit_status):
        if self._stdout_buffer.strip():
            self._dispatch_stdout_line(self._stdout_buffer.strip())
        self._stdout_buffer = ""
        self._stderr_buffer = ""

        if exit_code != 0 and self._pending_requests:
            self._fail_all_pending(f"后端会话异常退出，返回码: {exit_code}")

        if self._process is not None:
            process = self._process
            self._process = None
            process.deleteLater()

    def _fail_request(self, request_id: str, message: str):
        callbacks = self._pending_requests.pop(request_id, None)
        if callbacks is None:
            return
        if callbacks["on_error"] is not None:
            callbacks["on_error"](message)
        result = SessionResult(
            request_id=request_id,
            exit_code=1,
            message=message,
            all_lines=list(callbacks["all_lines"]),
        )
        if callbacks["on_finished"] is not None:
            callbacks["on_finished"](result)

    def _fail_all_pending(self, message: str):
        for request_id in list(self._pending_requests):
            self._fail_request(request_id, message)


class TaskPipeline(QObject):
    """统一管理前端的数据流水线任务，并维护常驻 C++ 后端会话。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread_pool = QThreadPool(self)
        self._thread_pool.setMaxThreadCount(max(2, min(4, os.cpu_count() or 2)))
        self._generation = 0
        self._backend = BackendSessionClient(self)

    def _next_generation(self) -> int:
        self._generation += 1
        return self._generation

    def _is_current(self, generation: int) -> bool:
        return generation == self._generation

    def cancel_active(self):
        self._next_generation()
        self._backend.restart()

    def restart_backend_session(self):
        self._backend.restart()

    def close_backend_session(self):
        self._backend.close()

    def load_dataset(
        self,
        input_file: str,
        threads: int,
        *,
        on_output: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_success: Callable[[SessionResult], None] | None = None,
        on_finished: Callable[[SessionResult], None] | None = None,
    ) -> int:
        generation = self._next_generation()

        def guard_output(message: str):
            if self._is_current(generation) and on_output is not None:
                on_output(message)

        def guard_error(message: str):
            if self._is_current(generation) and on_error is not None:
                on_error(message)

        def guard_success(result: SessionResult):
            if self._is_current(generation) and on_success is not None:
                on_success(result)

        def guard_finished(result: SessionResult):
            if self._is_current(generation) and on_finished is not None:
                on_finished(result)

        self._backend.load_dataset(
            input_file,
            threads,
            on_output=guard_output,
            on_error=guard_error,
            on_success=guard_success,
            on_finished=guard_finished,
        )
        return generation

    def run_backend_task(
        self,
        payload: dict[str, Any],
        *,
        on_output: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_success: Callable[[SessionResult], None] | None = None,
        on_finished: Callable[[SessionResult], None] | None = None,
    ) -> int:
        generation = self._next_generation()

        def guard_output(message: str):
            if self._is_current(generation) and on_output is not None:
                on_output(message)

        def guard_error(message: str):
            if self._is_current(generation) and on_error is not None:
                on_error(message)

        def guard_success(result: SessionResult):
            if self._is_current(generation) and on_success is not None:
                on_success(result)

        def guard_finished(result: SessionResult):
            if self._is_current(generation) and on_finished is not None:
                on_finished(result)

        self._backend.run_task(
            payload,
            on_output=guard_output,
            on_error=guard_error,
            on_success=guard_success,
            on_finished=guard_finished,
        )
        return generation

    def run_callable(
        self,
        fn: Callable[..., Any],
        *args: Any,
        on_success: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_progress: Callable[[Any], None] | None = None,
        on_finished: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> int:
        generation = self._next_generation()
        user_progress_callback = kwargs.get("progress_callback")
        task = _CallableTask(fn, args, kwargs)
        try:
            signature = inspect.signature(fn)
            accepts_progress = "progress_callback" in signature.parameters
        except (TypeError, ValueError):
            accepts_progress = False

        if accepts_progress:
            def progress_bridge(payload: Any):
                task.signals.progress.emit(payload)
                if callable(user_progress_callback):
                    user_progress_callback(payload)

            task.kwargs["progress_callback"] = progress_bridge

        def handle_success(result: Any):
            if self._is_current(generation) and on_success is not None:
                on_success(result)

        def handle_error(message: str):
            if self._is_current(generation) and on_error is not None:
                on_error(message)

        def handle_progress(payload: Any):
            if self._is_current(generation) and on_progress is not None:
                on_progress(payload)

        def handle_finished():
            if self._is_current(generation) and on_finished is not None:
                on_finished()

        task.signals.success.connect(handle_success)
        task.signals.error.connect(handle_error)
        task.signals.progress.connect(handle_progress)
        task.signals.finished.connect(handle_finished)
        self._thread_pool.start(task)
        return generation
