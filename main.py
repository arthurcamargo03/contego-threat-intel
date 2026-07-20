"""Ponto de entrada da aplicação FastAPI.

Camada de apresentação: recebe as requisições HTTP, orquestra os services (OTX e,
na Etapa 4, o de IA), persiste no banco e renderiza os templates. A regra de negócio
de verdade mora nos services — aqui só coordenamos e traduzimos erros em mensagens
amigáveis pro usuário (nunca deixando stack trace vazar pra tela).
"""

from pathlib import Path

from dotenv import load_dotenv

# Carrega o .env ANTES de importar os services, pois eles leem as chaves de os.environ
# no momento do import. Sem isso, OTX_API_KEY viria vazio.
load_dotenv()

from fastapi import FastAPI, Form, Request  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from fastapi.templating import Jinja2Templates  # noqa: E402

from database import db  # noqa: E402
from services import ai, otx  # noqa: E402

# Caminhos absolutos (baseados neste arquivo) pra app rodar de qualquer diretório.
BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Contego Threat Intel")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.on_event("startup")
def _startup() -> None:
    """Garante que a tabela do histórico exista quando a app sobe."""
    db.init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Página inicial: só o formulário de consulta (sem resultado ainda)."""
    return templates.TemplateResponse(request, "index.html")


@app.post("/", response_class=HTMLResponse)
def consultar(request: Request, indicator: str = Form(...)):
    """Processa a consulta de um indicador.

    Fluxo: chama o service do OTX -> salva no histórico -> renderiza o dashboard.
    Cada tipo de exceção do service vira uma mensagem clara na mesma página, sem
    quebrar a app nem expor detalhes técnicos.
    """
    try:
        result = otx.query_indicator(indicator)
    except otx.InvalidIndicatorError as e:
        # Erro do usuário (formato errado): explica o que se espera.
        return templates.TemplateResponse(
            request, "index.html",
            {"error": str(e), "last_input": indicator},
        )
    except otx.IndicatorNotFoundError:
        return templates.TemplateResponse(
            request, "index.html",
            {"error": "Indicador não encontrado no OTX.", "last_input": indicator},
        )
    except otx.OTXServiceError as e:
        # Falha externa (timeout, rate limit, API fora): mensagem amigável.
        return templates.TemplateResponse(
            request, "index.html",
            {"error": str(e), "last_input": indicator},
        )

    # Consulta OK. Gera o resumo de IA (opcional): se a chave não estiver
    # configurada ou a API falhar, ai_summary volta None e seguimos normalmente.
    ai_summary = ai.generate_summary(result)

    # Persiste no histórico já com o resumo (ou None).
    query_id = db.save_query(
        indicator=result["indicator"],
        indicator_type=result["indicator_type"],
        threat_level=result["threat_level"],
        pulse_count=result["pulse_count"],
        raw_response=result,
        ai_summary=ai_summary,
    )

    return templates.TemplateResponse(
        request, "index.html",
        {"result": result, "query_id": query_id, "ai_summary": ai_summary},
    )


@app.get("/history", response_class=HTMLResponse)
def history(request: Request):
    """Lista as consultas anteriores, mais recentes primeiro."""
    queries = db.get_history()
    return templates.TemplateResponse(
        request, "history.html", {"queries": queries}
    )


@app.get("/query/{query_id}", response_class=HTMLResponse)
def reopen_query(request: Request, query_id: int):
    """Reabre o resultado detalhado de uma consulta salva, sem reconsultar o OTX.

    Recupera o objeto tratado do banco (raw_response) e renderiza o mesmo dashboard
    da consulta ao vivo — por isso reaproveitamos o index.html.
    """
    record = db.get_query_by_id(query_id)
    if record is None:
        return templates.TemplateResponse(
            request, "index.html",
            {"error": "Consulta não encontrada no histórico."},
        )

    return templates.TemplateResponse(
        request, "index.html",
        {
            "result": record["raw_response"],
            "query_id": record["id"],
            "ai_summary": record["ai_summary"],  # já pensando na Etapa 4
        },
    )
