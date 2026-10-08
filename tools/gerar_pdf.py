#!/usr/bin/env python3
"""Converte um Markdown do projeto em HTML pronto para impressao/PDF."""
import sys
from pathlib import Path
import markdown

CSS = """
@page { size: A4; margin: 15mm 14mm; }
*{box-sizing:border-box}
body{font:10.2pt/1.45 "Source Sans 3","Segoe UI",Helvetica,Arial,sans-serif;color:#15202b;
  max-width:185mm;margin:0 auto;padding:10mm 6mm}
h1{font-size:19pt;margin:0 0 2mm;color:#0f2740;border-bottom:2px solid #0f2740;padding-bottom:2mm}
h2{font-size:12.5pt;margin:5mm 0 1.8mm;color:#134e7a;border-bottom:1px solid #d3dde6;padding-bottom:1mm;
  page-break-after:avoid}
h3{font-size:11pt;margin:4mm 0 1.5mm;color:#1b3a52;page-break-after:avoid}
p{margin:0 0 2.2mm;text-align:justify}
code{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;font-size:9pt;
  background:#eef3f7;padding:.5mm 1mm;border-radius:2px;color:#0b3d5c}
pre{background:#0f1720;color:#dbe6f0;padding:3mm 4mm;border-radius:3px;overflow-x:auto;
  font-size:8.6pt;line-height:1.42;page-break-inside:avoid}
pre code{background:none;color:inherit;padding:0;font-size:inherit}
table{width:100%;border-collapse:collapse;font-size:9pt;margin:2mm 0 4mm;page-break-inside:avoid}
th,td{border:1px solid #cfdae4;padding:1.6mm 2.2mm;text-align:left;vertical-align:top}
th{background:#eaf1f7;color:#0f2740;font-weight:600}
tr:nth-child(even) td{background:#f7fafc}
blockquote{border-left:3px solid #7fa8c8;margin:2mm 0;padding:1mm 0 1mm 4mm;color:#40566b;
  background:#f4f8fb}
ul,ol{margin:0 0 2.5mm;padding-left:6mm} li{margin:.8mm 0}
hr{border:0;border-top:1px solid #d3dde6;margin:5mm 0}
strong{color:#0f2740}
"""

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
body = markdown.markdown(src.read_text(encoding="utf-8"),
                         extensions=["tables", "fenced_code", "toc", "sane_lists"])
dst.write_text(
    f"<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>"
    f"<title>{src.stem}</title><style>{CSS}</style></head><body>{body}</body></html>",
    encoding="utf-8")
print(dst)
