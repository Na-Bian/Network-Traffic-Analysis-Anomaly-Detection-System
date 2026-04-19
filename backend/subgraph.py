import argparse
import sys

try:
    from backend.renderers import render_graph_html
except ModuleNotFoundError:
    from renderers import render_graph_html


def generate_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white", render_options=None):
    return render_graph_html(json_path, output_html_path, bgcolor, fontcolor, render_options=render_options)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bgcolor", default="#222222", help="背景颜色，例如 #222222")
    parser.add_argument("--fontcolor", default="white", help="文字颜色，例如 white")
    parser.add_argument("--render-mode", choices=["auto", "vis", "sigma"], default="auto")
    parser.add_argument("--top-k-edges", type=int, default=0)
    parser.add_argument("--aggregate-large-graph", action="store_true")
    args = parser.parse_args()
    try:
        generate_html(
            args.json, args.output, args.bgcolor, args.fontcolor,
            render_options={
                "render_mode": args.render_mode,
                "top_k_edges": args.top_k_edges,
                "aggregate_large_graph": args.aggregate_large_graph,
            }
        )
    except Exception as exc:
        print(exc)
        sys.exit(1)
