# Operational Defense Guide

O que a Rock House skill NÃO faz — e o que você deve configurar manualmente.

A skill analisa código. Estas defesas operam em runtime e precisam ser ativadas nos serviços.

## Cloudflare

| Defesa | Como Ativar |
|--------|------------|
| WAF | Dashboard → Security → WAF → Enable managed rules |
| Rate Limiting | Security → WAF → Rate limiting rules |
| DDoS | Ativo por padrão em todos os planos |
| Bot Management | Security → Bots |
| Attack Mode | Under Attack Mode → toggle quando sob ataque |

## Vercel

| Defesa | Como Ativar |
|--------|------------|
| Firewall | Settings → Firewall → Enable |
| Deployment Protection | Settings → General → Deployment Protection |
| Environment Variables | Settings → Environment Variables (nunca no código) |
| Logs | Observability → Runtime Logs |

## Supabase

| Defesa | Como Ativar |
|--------|------------|
| MFA | Authentication → Policies → Enable MFA |
| RLS | Table Editor → Enable RLS em cada tabela |
| Backups | Database → Backups (automático no Pro) |
| JWT Settings | Authentication → Settings → JWT expiry |

## Checklist Operacional

- [ ] WAF ativado (Cloudflare ou Vercel)
- [ ] Rate limiting configurado
- [ ] MFA habilitado para admin accounts
- [ ] Backups automáticos do banco
- [ ] Rotação de chaves documentada (a cada 90 dias)
- [ ] Logs de acesso habilitados
- [ ] Alertas de anomalia configurados
- [ ] Domínio com DNSSEC
- [ ] Email com SPF/DKIM/DMARC
