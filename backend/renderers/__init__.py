from .sigma_renderer import render_sigma_html
from .vis_renderer import _graph_mode, _load_graph, render_vis_html


def render_graph_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white", render_options=None,
                      data=None, progress_callback=None):
    render_options = render_options or {}
    if progress_callback:
        progress_callback("渲染进度: 准备读取图数据...")
    data = data if data is not None else _load_graph(json_path)
    if progress_callback:
        progress_callback(
            "渲染进度: 图数据已就绪，节点 {} 个，边 {} 条".format(
                len(data.get("nodes", [])),
                len(data.get("links", []))
            )
        )
    mode = _graph_mode(len(data.get("nodes", [])), len(data.get("links", [])))
    requested_renderer = render_options.get("render_mode", "auto")

    use_sigma = mode == "performance"
    if requested_renderer == "sigma":
        use_sigma = True
    elif requested_renderer == "vis":
        use_sigma = False

    if progress_callback:
        progress_callback(
            "渲染进度: 选择 {} 渲染器，模式={}".format(
                "sigma" if use_sigma else "vis-network",
                mode
            )
        )

    if use_sigma:
        return render_sigma_html(
            json_path, output_html_path, bgcolor, fontcolor,
            data=data, mode=mode, render_options=render_options, progress_callback=progress_callback
        )
    return render_vis_html(
        json_path, output_html_path, bgcolor, fontcolor,
        data=data, mode=mode, render_options=render_options, progress_callback=progress_callback
    )


__all__ = ["render_graph_html", "render_sigma_html", "render_vis_html"]
