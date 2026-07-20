"""Service de resumo em linguagem natural via Claude API (feature OPCIONAL).

Pega o objeto já tratado pelo service do OTX e pede pro Claude escrever um briefing
curto em PT-BR, no tom de um relatório pra cliente NÃO técnico.

Decisão de design mais importante: DEGRADAÇÃO GRACIOSA.
- Se a ANTHROPIC_API_KEY não estiver configurada, a função retorna None e a app
  funciona normalmente, só sem a seção "Resumo IA".
- Se a chamada à API falhar (rede, rate limit, etc.), também retorna None em vez de
  quebrar a consulta inteira — o dado do OTX é o que importa; o resumo é um extra.

Por isso NADA aqui levanta exceção pra cima: todo caminho de erro vira `None`.
"""

import os
from typing import Any, Optional

# Import "preguiçoso"/defensivo: se o pacote anthropic não estiver instalado, a app
# ainda sobe — só a feature de IA fica indisponível. Reforça o caráter opcional.
try:
    import anthropic
except ImportError:  # pragma: no cover
    anthropic = None  # type: ignore

# Modelo configurável por env (default barato/rápido, suficiente pro resumo).
MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5")

# Instrução de sistema: define o PAPEL e o TOM. Mantida fixa e clara para respostas
# consistentes — o conteúdo variável vai na mensagem do usuário.
_SYSTEM_PROMPT = (
    "Você é um analista de segurança da informação escrevendo um briefing curto "
    "para um cliente NÃO técnico. Escreva em português do Brasil, em 2 a 3 parágrafos, "
    "tom profissional e direto. Explique o que o indicador representa, o nível de risco "
    "e uma recomendação prática. Não use jargão sem explicar e não invente dados além "
    "dos fornecidos."
)


def _build_user_prompt(result: dict[str, Any]) -> str:
    """Monta o texto com os dados relevantes do indicador para o Claude resumir.

    Enviamos só um resumo estruturado (não o objeto inteiro) para gastar menos tokens
    e focar o modelo no que importa. Campos ausentes por tipo simplesmente não entram.
    """
    linhas = [
        f"Indicador: {result.get('indicator')}",
        f"Tipo: {result.get('indicator_type')}",
        f"Veredito: {result.get('threat_level')}",
        f"Pulses relacionados (relatos de ameaça): {result.get('pulse_count')}",
    ]

    pulses = result.get("pulses") or {}
    if pulses.get("names"):
        linhas.append("Nomes dos pulses: " + "; ".join(pulses["names"]))
    if pulses.get("malware_families"):
        linhas.append("Famílias de malware citadas: " + ", ".join(pulses["malware_families"]))

    geo = result.get("geo") or {}
    if geo.get("country") or geo.get("asn"):
        linhas.append(
            f"Localização: país={geo.get('country')}, cidade={geo.get('city')}, "
            f"ASN={geo.get('asn')}"
        )

    fa = result.get("file_analysis") or {}
    if fa.get("file_type"):
        linhas.append(f"Tipo do arquivo: {fa.get('file_type')}")

    return (
        "Escreva o briefing sobre este indicador de ameaça:\n\n"
        + "\n".join(linhas)
    )


def generate_summary(result: dict[str, Any]) -> Optional[str]:
    """Gera o briefing em PT-BR, ou None se a feature não estiver disponível.

    Args:
        result: objeto limpo devolvido por otx.query_indicator.

    Returns:
        O texto do resumo, ou None quando a chave não está configurada, o SDK não
        está instalado, ou a API falhou (a app não deve quebrar por causa disso).
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")

    # Guarda de degradação: sem SDK ou sem chave -> feature simplesmente desligada.
    if anthropic is None or not api_key:
        return None

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=MODEL,
            # max_tokens baixo de propósito: o briefing é curto (2-3 parágrafos).
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_user_prompt(result)}],
        )
        # A resposta é uma lista de blocos; pegamos o texto do(s) bloco(s) de texto.
        partes = [bloco.text for bloco in message.content if bloco.type == "text"]
        texto = "\n".join(partes).strip()
        return texto or None
    except Exception:
        # Qualquer falha (rede, rate limit, chave inválida...) degrada pra None.
        # Não relançamos: o resumo é opcional e não pode derrubar a consulta.
        return None
