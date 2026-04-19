from .sigma_renderer import render_sigma_html
from .vis_renderer import _graph_mode, _load_graph, render_vis_html


def render_graph_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white"):
    data = _load_graph(json_path)
    mode = _graph_mode(len(data.get("nodes", [])), len(data.get("links", [])))
    if mode == "performance":
        return render_sigma_html(json_path, output_html_path, bgcolor, fontcolor, data=data, mode=mode)
    return render_vis_html(json_path, output_html_path, bgcolor, fontcolor, data=data, mode=mode)


__all__ = ["render_graph_html", "render_sigma_html", "render_vis_html"]
