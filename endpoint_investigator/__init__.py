"""Endpoint Investigator - investigacao de endpoints GNU/Linux por correlacao.

Pipeline: COLETA -> NORMALIZACAO -> CORRELACAO -> EVIDENCIAS -> HIPOTESES -> RESULTADO.
A camada opcional de IA (``ai/``) e a ultima e recebe apenas o bundle ja
estruturado, nunca os dados brutos.
"""

__version__ = "1.0.0"
__authors__ = ("Kauã Figueira Santos", "Matheus Constante")
__course__ = "Tecnologias Hackers - Insper - Prof. Dr. Rodolfo Avelino"

__all__ = ["__version__", "__authors__", "__course__"]
