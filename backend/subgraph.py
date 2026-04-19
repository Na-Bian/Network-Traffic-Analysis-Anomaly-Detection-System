import argparse
import sys

try:
    from backend.renderers import render_graph_html
except ModuleNotFoundError:
    from renderers import render_graph_html


def generate_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white"):
    return render_graph_html(json_path, output_html_path, bgcolor, fontcolor)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bgcolor", default="#222222", help="背景颜色，例如 #222222")
    parser.add_argument("--fontcolor", default="white", help="文字颜色，例如 white")
    args = parser.parse_args()
    try:
        generate_html(args.json, args.output, args.bgcolor, args.fontcolor)
    except Exception as exc:
        print(exc)
        sys.exit(1)
