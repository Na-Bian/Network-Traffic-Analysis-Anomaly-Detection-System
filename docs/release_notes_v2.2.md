# NetworkAnalyzer 2.2 Release Notes

Release baseline: GitHub [`v2.1`](https://github.com/Na-Bian/Network-Traffic-Analysis-Anomaly-Detection-System/releases/tag/v2.1) at commit `5b6f27f`

## Highlights

### 1. Backend session architecture

- Replaced the one-shot task CLI path in the GUI with a dedicated persistent C++ backend session.
- Dataset loading now builds the graph once per session and keeps it in memory for follow-up analysis requests.
- The GUI now sends structured requests instead of rebuilding command lines for every analysis task.

### 2. Multithreading and performance

- Optimized the graph-load pipeline around CSV parsing, graph construction, index warmup, and neighbor-cache preparation.
- Reworked read-only anomaly analysis so port scan, DDoS target, and star-structure detection can better exploit multiple CPU cores.
- Added broader result reuse and reduced repeated graph work across full-graph export, traffic analysis, and anomaly detection.

### 3. Observability and long-task progress

- Added staged progress reporting for PCAP parsing, CSV loading, graph build, index warmup, analysis, JSON export, and HTML rendering.
- The GUI automatically shifts to the log/results context for long-running tasks so users can see progress in real time.
- Full-graph and subgraph rendering now expose finer render-phase logs rather than a single opaque wait state.

### 4. UX and stability polish

- Added empty-result prompts for anomaly tasks and synchronized the related i18n strings.
- Added interface font selection in Settings and ensured About / settings-related views follow the active UI font.
- Added GitHub release update checking and normalized version display formatting around `2.2`.
- Polished several settings-page alignment, About refresh, and localized progress-log details.
