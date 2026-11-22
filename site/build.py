#!/usr/bin/env python3
"""Build the site from content/: every .md -> .html, copy static/, write sitemap.xml.

Usage (from anywhere): python3 site/build.py   -> output in _site/
"""
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
CONTENT = ROOT / "content"
OUT = ROOT / "_site"
TEMPLATE = ROOT / "site" / "template.html"
BASE_URL = "https://offsecnotes.frankheat.io"
NO_TOC = {"index.md", "references.md"}


def lastmod(rel):
    # Date of the last real edit (pure renames/moves are ignored).
    out = subprocess.run(["git", "log", "-1", "--follow", "--diff-filter=AM", "--format=%cs", "--", rel],
                         cwd=CONTENT, capture_output=True, text=True).stdout.strip()
    return f"<lastmod>{out}</lastmod>" if out else ""


def build(rel):
    html = OUT / rel.with_suffix(".html")
    html.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["pandoc", rel, "-o", html, "--template", TEMPLATE, "--wrap=none",
           "-f", "markdown+lists_without_preceding_blankline"]
    if rel.name not in NO_TOC:
        cmd += ["--toc", "--toc-depth=6"]
    subprocess.run(cmd, cwd=CONTENT, check=True)

    path = rel.with_suffix(".html").as_posix().removesuffix("index.html")
    return f"<url><loc>{BASE_URL}/{quote(path)}</loc>{lastmod(rel)}</url>"


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(CONTENT / "static", OUT / "static")

    sources = sorted(md.relative_to(CONTENT) for md in CONTENT.rglob("*.md"))
    with ThreadPoolExecutor() as pool:
        urls = list(pool.map(build, sources))

    (OUT / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls) + "\n</urlset>\n")
    print(f"Built {len(urls)} pages in {OUT}")


if __name__ == "__main__":
    main()
