"""Camada de RESULTADO: console, JSON e HTML a partir do mesmo bundle."""

from .console import render_console
from .html_report import render_html
from .json_report import render_json

__all__ = ["render_console", "render_json", "render_html"]
