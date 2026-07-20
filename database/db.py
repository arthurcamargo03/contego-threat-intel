"""Camada de acesso ao banco SQLite.

Toda interação com o banco fica isolada aqui (padrão de camadas): as rotas e os
services nunca escrevem SQL diretamente, só chamam funções deste módulo. Isso deixa
o resto da app agnóstico ao banco — se um dia trocar SQLite por Postgres, muda só
este arquivo.

A tabela `queries` guarda o histórico de consultas de IOCs.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

# Caminho do arquivo do banco via env (com default sensato). Mantém a config fora
# do código e permite apontar para outro arquivo em testes, por exemplo.
DB_PATH = os.getenv("DATABASE_PATH", "threat_intel.db")


def _connect() -> sqlite3.Connection:
    """Abre uma conexão com o SQLite.

    row_factory = sqlite3.Row faz cada linha se comportar como dict (acesso por
    nome de coluna, ex: row["indicator"]), o que deixa o código que consome os
    dados muito mais legível do que índices numéricos.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Cria a tabela `queries` se ainda não existir.

    Chamada uma vez no startup da app (evento de startup do FastAPI). É idempotente
    graças ao IF NOT EXISTS, então rodar várias vezes não causa erro.
    """
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS queries (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator      TEXT    NOT NULL,   -- o IOC consultado (IP/domínio/hash)
                indicator_type TEXT    NOT NULL,   -- "ipv4" | "domain" | "hash"
                threat_level   TEXT    NOT NULL,   -- "limpo" | "suspeito" | "malicioso"
                pulse_count    INTEGER NOT NULL,   -- nº de pulses do OTX (sinal principal)
                ai_summary     TEXT,               -- resumo do Claude; NULL se não gerado
                raw_response   TEXT    NOT NULL,   -- objeto limpo (JSON) p/ re-renderizar o detalhe
                created_at     TEXT    NOT NULL    -- timestamp ISO 8601 (UTC) da consulta
            )
            """
        )


def save_query(
    indicator: str,
    indicator_type: str,
    threat_level: str,
    pulse_count: int,
    raw_response: dict[str, Any],
    ai_summary: Optional[str] = None,
) -> int:
    """Persiste uma consulta no histórico e devolve o id gerado.

    `raw_response` é o objeto JÁ TRATADO pelo service (não o JSON cru do OTX). Guardar
    ele serializado permite reabrir o detalhe de uma consulta antiga direto do banco,
    sem precisar bater no OTX de novo (mais rápido e não gasta rate limit).

    Args:
        indicator: o IOC consultado.
        indicator_type: tipo detectado ("ipv4", "domain" ou "hash").
        threat_level: veredito derivado dos pulses.
        pulse_count: quantidade de pulses relacionados.
        raw_response: dict limpo com os dados exibidos no dashboard.
        ai_summary: briefing do Claude, se gerado; senão None.

    Returns:
        O id (chave primária) da linha inserida.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO queries
                (indicator, indicator_type, threat_level, pulse_count,
                 ai_summary, raw_response, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                indicator,
                indicator_type,
                threat_level,
                pulse_count,
                ai_summary,
                # Serializa o dict para texto; ensure_ascii=False preserva acentos.
                json.dumps(raw_response, ensure_ascii=False),
                created_at,
            ),
        )
        # lastrowid = id autoincrement da linha recém-inserida.
        return cursor.lastrowid


def get_history(limit: int = 50) -> list[dict[str, Any]]:
    """Lista o histórico de consultas, mais recentes primeiro.

    Para a página de histórico não precisamos do raw_response inteiro (payload
    grande), então selecionamos só as colunas do resumo — mais leve.

    Args:
        limit: máximo de linhas a retornar.

    Returns:
        Lista de dicts, um por consulta, ordenados do mais novo pro mais antigo.
    """
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, indicator, indicator_type, threat_level, pulse_count, created_at
            FROM queries
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    # sqlite3.Row -> dict comum para o template/JSON consumir sem surpresa.
    return [dict(row) for row in rows]


def get_query_by_id(query_id: int) -> Optional[dict[str, Any]]:
    """Busca uma consulta pelo id e reidrata o raw_response.

    Usada pelo link "reabrir resultado" da página de histórico: recupera o objeto
    tratado que foi salvo e o desserializa de volta pra dict, pronto pra re-render
    do dashboard sem nova chamada ao OTX.

    Returns:
        Dict da consulta (com `raw_response` já como dict), ou None se o id não existir.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM queries WHERE id = ?", (query_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    # Desfaz o json.dumps do save_query: volta a ser dict aninhado.
    result["raw_response"] = json.loads(result["raw_response"])
    return result
