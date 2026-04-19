from .sigma_renderer import render_sigma_html
from .vis_renderer import _graph_mode, _load_graph, render_vis_html


def render_graph_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white", render_options=None):
    render_options = render_options or {}
    data = _load_graph(json_path)
    mode = _graph_mode(len(data.get("nodes", [])), len(data.get("links", [])))
    requested_renderer = render_options.get("render_mode", "auto")

    use_sigma = mode == "performance"
    if requested_renderer == "sigma":
        use_sigma = True
    elif requested_renderer == "vis":
        use_sigma = False

    if use_sigma:
        return render_sigma_html(
            json_path, output_html_path, bgcolor, fontcolor,
            data=data, mode=mode, render_options=render_options
        )
    return render_vis_html(
        json_path, output_html_path, bgcolor, fontcolor,
        data=data, mode=mode, render_options=render_options
    )


__all__ = ["render_graph_html", "render_sigma_html", "render_vis_html"]
