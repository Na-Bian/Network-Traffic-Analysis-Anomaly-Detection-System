# AGENTS Guide

## Project Purpose
- This is a single-binary C++ network traffic analyzer that builds a directed IP graph from CSV records, then runs topology/path/security analyses.
- Main CLI entrypoint is `main.cpp`; `benchmark.cpp` is a separate performance harness.

## Architecture You Need First
- Core model is `Graph` (`Graph.h`, `Graph.cpp`) wrapping `Vertices` (`Vertices.h`) and per-vertex `Edges` (`Edges.h`).
- `Graph::addRecord(...)` is the ingestion boundary: creates vertices, updates in/out/HTTPS counters, and merges edge stats by destination.
- `Edges` aggregate per `(srcIndex -> dstIndex)` with protocol-level stats and `(srcPort,dstPort)` sets; this is reused by anomaly detection and custom rules.
- Path algorithms live in `pathSearch.cpp` via shared `minCost(...)` (Dijkstra + predecessor backtracking), then wrapped as `minCongestion`, `minHop`, `minCostCustom`.
- JSON export is isolated in `SubgraphExporter.h`; tasks in `main.cpp` call Graph methods then exporter methods.

## Data Flow and Task Boundaries
- CSV pipeline: `CSVReader::readCSV()` does two passes: (1) collect unique IPs for `Graph::reserve`, (2) parse chunks in parallel and call `graph.addRecord` under one mutex.
- Expected CSV column order (after header): `srcIP,dstIP,protocol,srcPort,dstPort,dataSize,duration` (`CSVReader.h`).
- CLI dispatch is task-string based in `main.cpp` (`full-graph`, `subgraph`, `flow-sort`, `min-*`, `compare-paths`, `port-scan`, `ddos-target`, `star-structures`, `custom-rule`).
- `CustomRule` (`CustomRule.h`) evaluates target-IP neighbor communications against CIDR/range/protocol/port/traffic constraints and returns `ViolationRecord` set.

## Build and Run Workflow
- No `CMakeLists.txt` or test framework is present; build manually with a C++20 compiler.
- Do not compile `main.cpp` and `benchmark.cpp` together (both define `main`).
- App build (g++ example):
  - `g++ -std=c++20 -O2 main.cpp Graph.cpp pathSearch.cpp -o analyzer.exe`
- Benchmark build:
  - `g++ -std=c++20 -O2 benchmark.cpp Graph.cpp pathSearch.cpp -o benchmark.exe`
- Typical run:
  - `./analyzer.exe --input data.csv --task full-graph --output-json full.json`
  - `./analyzer.exe --input data.csv --task compare-paths --src 10.0.0.1 --dst 10.0.0.2 --output-json paths.json`

## Project-Specific Conventions and Gotchas
- `Graph.h` includes `"vertices.h"` while file is `Vertices.h`; this works on Windows but can break on case-sensitive filesystems.
- `main.cpp` includes `<windows.h>` directly and only guards `SetConsoleOutputCP` with `_WIN32`; non-Windows builds will fail unless include handling is adjusted.
- Many APIs return value objects (`PathInfo`, `ConnectedComponents`, tuple sets) rather than mutating global state; follow this style for new analyses.
- Export JSON schema is stable: `nodes` with `{id,label,group}` and `links` with `{source,target,value}`; multi-strategy path export adds `groups` on links.

## Existing AI Instruction Sources
- Searched for existing AI instruction files (`copilot-instructions`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, etc.) and none were found in this repository.

