# Contego Threat Intel

Plataforma web simples de **Threat Intelligence** para consulta de indicadores de
ameaça (IOCs). O usuário informa um **IP**, **domínio** ou **hash de arquivo**, e a
aplicação consulta a API do [AlienVault OTX](https://otx.alienvault.com/), organiza os
dados de reputação/ameaça num dashboard legível, guarda um histórico local e — como
diferencial — gera um resumo em linguagem natural (PT-BR) via **Claude API**, no formato
de um briefing para o cliente.

> Projeto desenvolvido como desafio técnico de estágio na **Contego Security**.

## Stack

- **Backend:** Python + FastAPI
- **Frontend:** HTML/CSS/JS com Jinja2 (sem frameworks JS)
- **Banco:** SQLite (histórico de consultas)
- **APIs externas:** AlienVault OTX (dados de ameaça) + Anthropic Claude (resumo em linguagem natural)

## Status

🚧 Em construção. Este README será detalhado ao longo do desenvolvimento com o passo a
passo de instalação, obtenção das chaves de API e explicação do fluxo da aplicação.
