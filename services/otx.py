"""Service de consulta ao AlienVault OTX.

Responsabilidade única: dado um texto (IP, domínio ou hash), detectar o tipo,
consultar os endpoints certos do OTX, tratar a resposta e devolver um objeto LIMPO
pronto pro dashboard — nunca o JSON cru da API.

Decisões de design importantes:
- A estrutura dos campos usados aqui foi VERIFICADA contra respostas reais do OTX
  (não inventada). Ex: IP `/general` já traz geo embutido; domínio precisa de `/geo`
  à parte; hash usa `/analysis`.
- Erros da API viram exceções próprias (InvalidIndicator / NotFound / OTXServiceError)
  para a camada de rotas traduzir em mensagem amigável, sem vazar stack trace.
"""

import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

# Config via env (com defaults sensatos). URL base separada facilita apontar p/ mock em teste.
BASE_URL = os.getenv("OTX_BASE_URL", "https://otx.alienvault.com")
API_KEY = os.getenv("OTX_API_KEY", "")
TIMEOUT = 15.0  # segundos; evita a app travar se o OTX ficar lento/pendurado.


# --- Exceções próprias -------------------------------------------------------
# Separar por tipo deixa a rota decidir a mensagem e o status HTTP certo pro usuário.

class InvalidIndicatorError(Exception):
    """Texto informado não é IP, domínio nem hash válido."""


class IndicatorNotFoundError(Exception):
    """OTX não conhece esse indicador (HTTP 404)."""


class OTXServiceError(Exception):
    """Falha ao falar com o OTX: timeout, rate limit, API fora do ar, etc."""


# --- Detecção de tipo por regex ---------------------------------------------
# Regex compiladas uma vez no import (mais eficiente que recompilar a cada consulta).

# IPv4: quatro octetos 0-255 separados por ponto.
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
# Hashes: contagem exata de dígitos hex define o algoritmo (MD5=32, SHA1=40, SHA256=64).
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
# Domínio: rótulos alfanuméricos separados por ponto, com TLD de 2+ letras no fim.
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def detect_indicator_type(value: str) -> Optional[str]:
    """Detecta o tipo do indicador via regex, sem pedir nada ao usuário.

    A ORDEM importa: testamos IP e hash antes de domínio porque são padrões mais
    estritos. Um hash não casa com domínio (não tem ponto), mas manter IP/hash
    primeiro evita ambiguidade.

    Returns:
        "ipv4", "hash" ou "domain"; ou None se não casar com nenhum.
    """
    v = value.strip()
    if _IPV4_RE.match(v):
        return "ipv4"
    if _MD5_RE.match(v) or _SHA1_RE.match(v) or _SHA256_RE.match(v):
        return "hash"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def _derive_threat_level(pulse_count: int) -> str:
    """Traduz o nº de pulses num veredito simples.

    O pulse_info é o sinal principal de ameaça no OTX (quantos relatórios citam o
    indicador). Regra do desafio: 0 = limpo, 1-3 = suspeito, 4+ = malicioso.
    """
    if pulse_count == 0:
        return "limpo"
    if pulse_count <= 3:
        return "suspeito"
    return "malicioso"


# --- Chamada HTTP ------------------------------------------------------------

def _get(client: httpx.Client, path: str) -> dict[str, Any]:
    """GET num endpoint do OTX, com tratamento de erro centralizado.

    Converte cada modo de falha numa exceção própria com mensagem clara. Fica tudo
    num lugar só pra não repetir try/except em cada chamada.
    """
    if not API_KEY:
        raise OTXServiceError("Chave da API do OTX não configurada (OTX_API_KEY).")

    url = f"{BASE_URL}{path}"
    try:
        resp = client.get(url, headers={"X-OTX-API-KEY": API_KEY})
    except httpx.TimeoutException:
        raise OTXServiceError("O OTX demorou demais para responder (timeout).")
    except httpx.RequestError:
        # Erro de rede/DNS/conexão: API provavelmente fora do ar.
        raise OTXServiceError("Não foi possível conectar ao OTX.")

    if resp.status_code == 404:
        raise IndicatorNotFoundError("Indicador não encontrado no OTX.")
    if resp.status_code == 429:
        raise OTXServiceError("Limite de requisições do OTX atingido (rate limit).")
    if resp.status_code >= 400:
        raise OTXServiceError(f"OTX retornou erro HTTP {resp.status_code}.")

    return resp.json()


# --- Extração dos pulses (comum a todos os tipos) ---------------------------

def _extract_pulses(general: dict[str, Any]) -> dict[str, Any]:
    """Resume o pulse_info: contagem + nomes e metadados úteis dos pulses.

    Limita a 10 nomes pra não poluir a tela quando um indicador tem dezenas de
    pulses. Agrega famílias de malware e tags citadas nos pulses (campos que
    confirmei existirem na resposta real).
    """
    pulse_info = general.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    count = pulse_info.get("count", 0) or 0

    names = [p.get("name") for p in pulses if p.get("name")][:10]

    # set() para deduplicar; depois vira lista ordenada só p/ exibição estável.
    # No OTX real: malware_families é lista de DICTS ({id, display_name, target}),
    # já tags é lista de strings. Por isso o tratamento difere entre os dois.
    malware_families: set[str] = set()
    tags: set[str] = set()
    for p in pulses:
        for fam in p.get("malware_families") or []:
            name = fam.get("display_name") or fam.get("id")
            if name:
                malware_families.add(name)
        tags.update(p.get("tags") or [])

    return {
        "count": count,
        "names": names,
        "malware_families": sorted(malware_families),
        "tags": sorted(tags)[:15],
    }


def _extract_geo(data: dict[str, Any]) -> dict[str, Any]:
    """Extrai geolocalização de um payload que contenha os campos geo do OTX.

    Serve tanto pro IP (geo vem no /general) quanto pro domínio (geo vem no /geo).
    """
    return {
        "country": data.get("country_name"),
        "city": data.get("city"),
        "asn": data.get("asn"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
    }


# --- Consulta principal ------------------------------------------------------

def query_indicator(raw_value: str) -> dict[str, Any]:
    """Consulta um indicador no OTX e devolve um objeto limpo pro frontend.

    Fluxo: detecta o tipo -> chama os endpoints do tipo -> monta o dict de saída.
    O dict retornado é o que vai pro dashboard E o que é salvo (raw_response) no banco.

    Raises:
        InvalidIndicatorError: se o texto não for IP/domínio/hash.
        IndicatorNotFoundError: se o OTX não conhecer o indicador (404).
        OTXServiceError: timeout, rate limit ou API fora do ar.
    """
    value = raw_value.strip()
    ind_type = detect_indicator_type(value)
    if ind_type is None:
        raise InvalidIndicatorError(
            "Formato inválido. Informe um IPv4, domínio ou hash (MD5/SHA1/SHA256)."
        )

    # Um client só por consulta: reaproveita a conexão entre os vários endpoints.
    with httpx.Client(timeout=TIMEOUT) as client:
        result: dict[str, Any] = {
            "indicator": value,
            "indicator_type": ind_type,
            # timestamp da consulta, em UTC ISO 8601.
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }

        if ind_type == "ipv4":
            general = _get(client, f"/api/v1/indicators/IPv4/{value}/general")
            result["pulses"] = _extract_pulses(general)
            result["geo"] = _extract_geo(general)  # IP já traz geo no /general
            result["malware"] = _extract_malware(
                _get(client, f"/api/v1/indicators/IPv4/{value}/malware")
            )

        elif ind_type == "domain":
            general = _get(client, f"/api/v1/indicators/domain/{value}/general")
            result["pulses"] = _extract_pulses(general)
            # Domínio NÃO traz geo no /general: precisa do endpoint /geo à parte.
            result["geo"] = _extract_geo(
                _get(client, f"/api/v1/indicators/domain/{value}/geo")
            )
            result["malware"] = _extract_malware(
                _get(client, f"/api/v1/indicators/domain/{value}/malware")
            )
            result["urls"] = _extract_urls(
                _get(client, f"/api/v1/indicators/domain/{value}/url_list")
            )

        else:  # hash
            general = _get(client, f"/api/v1/indicators/file/{value}/general")
            result["pulses"] = _extract_pulses(general)
            result["file_analysis"] = _extract_file_analysis(
                _get(client, f"/api/v1/indicators/file/{value}/analysis")
            )

    # Veredito derivado da contagem de pulses.
    result["pulse_count"] = result["pulses"]["count"]
    result["threat_level"] = _derive_threat_level(result["pulse_count"])
    return result


# --- Extratores específicos por tipo ----------------------------------------

def _extract_malware(payload: dict[str, Any]) -> dict[str, Any]:
    """Resume malware associado (endpoint /malware de IP/domínio).

    Uso defensivo de .get(): se o OTX mudar o formato dos itens, retorna None em vez
    de quebrar. Limita a 10 amostras pra não estourar a tela.
    """
    data = payload.get("data") or []
    samples = [
        {"hash": item.get("hash"), "detections": item.get("detections")}
        for item in data[:10]
    ]
    return {"count": payload.get("count", 0) or 0, "samples": samples}


def _extract_urls(payload: dict[str, Any]) -> dict[str, Any]:
    """Resume URLs associadas a um domínio (endpoint /url_list).

    actual_size é o total real de URLs; mostramos só as 10 primeiras no dashboard.
    """
    url_list = payload.get("url_list") or []
    items = [{"url": u.get("url"), "date": u.get("date")} for u in url_list[:10]]
    return {"count": payload.get("actual_size", 0) or 0, "items": items}


def _extract_file_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    """Extrai dados de análise de um hash (endpoint /analysis).

    Os campos úteis ficam aninhados em analysis.info.results (confirmado na resposta
    real): md5/sha1/sha256, tipo e tamanho do arquivo.
    """
    analysis = payload.get("analysis") or {}
    results = (analysis.get("info") or {}).get("results") or {}
    return {
        "md5": results.get("md5"),
        "sha1": results.get("sha1"),
        "sha256": results.get("sha256"),
        "file_type": results.get("file_type"),
        "file_class": results.get("file_class"),
        "filesize": results.get("filesize"),
        "ssdeep": results.get("ssdeep"),
        # tags pode vir vazio; mantemos como lista p/ o template iterar sem checagem.
        "tags": results.get("tags") or [],
    }
