# OWASP API Security Top 10:2023 — Referência PT-BR

Referência para vulnerabilidades específicas de APIs.

## As 10 Categorias

| # | Categoria | Exemplo em Vibe Coding |
|---|-----------|----------------------|
| API1 | **Falha de Autorização em Nível de Objeto** | GET /api/users/123 → trocar pra /api/users/456 sem verificar ownership. |
| API2 | **Falha de Autenticação** | JWT sem verificação, token sem expiração, API key exposta no client. |
| API3 | **Falha de Autorização em Nível de Propriedade** | Retornar campos sensíveis (senha, role) na resposta da API. Mass assignment. |
| API4 | **Consumo Irrestrito de Recursos** | Sem rate limiting, sem paginação, sem limite de tamanho de upload. |
| API5 | **Falha de Autorização em Nível de Função** | Usuário comum acessa endpoint /api/admin/ sem verificação de role. |
| API6 | **Acesso Irrestrito a Fluxos de Negócio** | Bot compra 1000 ingressos, spammer cria 1000 contas em loop. |
| API7 | **SSRF** | API busca URL do body sem validar → acessa rede interna. |
| API8 | **Gerenciamento de Inventário Inadequado** | APIs antigas/não documentadas expostas sem proteção. |
| API9 | **Consumo Inseguro de APIs** | App confia em dados de API de terceiros sem validar. |
| API10 | **Uso Inseguro de APIs** | Client-side SDK mal configurado, chaves expostas. |
