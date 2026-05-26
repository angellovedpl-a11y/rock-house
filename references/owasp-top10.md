# OWASP Top 10:2021 — Referência PT-BR

Referência rápida para o relatório de auditoria. Carregue apenas quando citar uma categoria OWASP.

## As 10 Categorias

| # | Categoria | Exemplo em Vibe Coding |
|---|-----------|----------------------|
| A01 | **Quebra de Controle de Acesso** | IDOR — trocar ID na URL e acessar dados alheios. RLS desligado no Supabase. |
| A02 | **Falhas Criptográficas** | Senha em plaintext, JWT sem expiração, HTTP sem TLS. |
| A03 | **Injeção** | SQL concatenado com f-string, innerHTML com input do usuário, prompt injection. |
| A04 | **Design Inseguro** | App sem rate limiting, sem validação server-side, auth só no client. |
| A05 | **Configuração Incorreta** | Debug mode em produção, CORS aberto, headers ausentes, .env no git. |
| A06 | **Componentes Vulneráveis** | npm install sem audit, dependências desatualizadas com CVEs conhecidos. |
| A07 | **Falhas de Autenticação** | Senha fraca sem validação, sessão sem expiração, credential stuffing sem proteção. |
| A08 | **Falhas de Integridade** | CI/CD sem verificação, scripts externos sem SRI, updates automáticos não assinados. |
| A09 | **Falhas de Logging e Monitoramento** | Sem logs de login falho, sem alertas de anomalia, sem audit trail. |
| A10 | **SSRF** | Server busca URL do usuário sem validar, acessa rede interna ou metadata AWS. |

## Como Citar no Relatório

No finding, referencie a categoria relevante:

> **Categoria OWASP:** A01 — Quebra de Controle de Acesso
