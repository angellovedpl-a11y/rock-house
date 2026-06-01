function isClientPath(rel) {
  return /(^|\/)(app|pages|components|hooks)\//.test(rel) && !/\/api\//.test(rel) && !/server/.test(rel);
}

module.exports = [
  {
    id: 'S4', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    pattern: /NEXT_PUBLIC_.*(SERVICE|SECRET|PRIVATE|ADMIN|PASSWORD)/i,
    message: 'Sensitive-looking NEXT_PUBLIC variable exposed to client bundle.',
    recommendation: 'Move the value to a server-only environment variable.',
    fixPack: {
      why: 'Tudo com prefixo NEXT_PUBLIC_ vai pro bundle do cliente — qualquer um lê.',
      before: 'NEXT_PUBLIC_SERVICE_KEY=...',
      after: 'SERVICE_KEY=...   // sem NEXT_PUBLIC_, só no servidor',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'A1', severity: 'Critico', vector: 'Auth & Access', languages: ['*'],
    pathTest: isClientPath,
    pattern: /SUPABASE_SERVICE_ROLE|service_role/i,
    message: 'Supabase service role reference appears in client-side code.',
    recommendation: 'Use service role only in server routes or server actions.',
    fixPack: {
      why: 'A service_role ignora RLS; no cliente, é acesso total ao banco pra qualquer visitante.',
      before: "createClient(url, SUPABASE_SERVICE_ROLE)  // em components/",
      after: "// service_role só em route handlers / server actions",
      refs: ['OWASP A01', 'CWE-200']
    }
  },
  {
    id: 'S7', severity: 'Alto', vector: 'Secrets', languages: ['*'],
    pattern: /error\.stack|err\.stack/,
    message: 'Stack trace appears in client-visible error response.',
    recommendation: 'Log internal details server-side and return a generic error.',
    fixPack: {
      why: 'Stack trace revela caminhos, libs e versões que ajudam o atacante.',
      before: 'res.status(500).json({ error: err.stack })',
      after: 'console.error(err); res.status(500).json({ error: "Erro interno" })',
      refs: ['OWASP A05', 'CWE-209']
    }
  },
  {
    id: 'A3', severity: 'Alto', vector: 'Auth & Access', languages: ['js'],
    pattern: /\.eq\(['"]id['"],\s*params\.id\)/,
    flow: { context: 8, negate: /user_id|owner|auth\.|getServerSession|getUser|session/ },
    message: 'ID lookup does not show an ownership/auth check nearby.',
    recommendation: 'Add ownership filtering such as user_id = authenticated user id.',
    fixPack: {
      why: 'Buscar por id sem checar dono = IDOR: troco o id na URL e leio dados alheios.',
      before: ".eq('id', params.id)",
      after: ".eq('id', params.id).eq('user_id', session.user.id)",
      refs: ['OWASP A01 / API1:2023', 'CWE-639']
    }
  }
];
