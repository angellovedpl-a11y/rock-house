const DEFAULT_PATHS = ['/'];
const STACK_PATTERNS = [
  /ReferenceError:/,
  /TypeError:/,
  /SyntaxError:/,
  /\bat [^(]+ \([^)]+:\d+:\d+\)/,
  /\bat [^ ]+:\d+:\d+/,
  /UnhandledPromiseRejection/i
];

async function runDast(options) {
  const {
    dast,
    addFinding,
    addUnknown,
    gates,
    fail
  } = options;

  if (!dast || !dast.url) {
    return {
      configured: false,
      executed: false,
      url: null,
      paths: []
    };
  }

  let baseUrl;
  try {
    baseUrl = new URL(dast.url);
  } catch (error) {
    fail(`Invalid DAST URL "${dast.url}": ${error.message}`);
  }

  const paths = normalizePaths(dast.paths);
  const timeoutMs = Number.isFinite(dast.timeoutMs) ? dast.timeoutMs : 5000;
  const targets = paths.map((targetPath) => new URL(targetPath, baseUrl).toString());
  const seen = new Set();
  const uniqueTargets = targets.filter((target) => {
    if (seen.has(target)) return false;
    seen.add(target);
    return true;
  });

  let executed = false;
  for (let index = 0; index < uniqueTargets.length; index += 1) {
    const target = uniqueTargets[index];
    try {
      const response = await fetchWithTimeout(target, timeoutMs);
      executed = true;
      const body = await response.text();
      inspectResponse({
        url: target,
        isPrimary: index === 0,
        response,
        body,
        addFinding,
        gates
      });
    } catch (error) {
      addUnknown(
        'H6',
        'Headers & CORS',
        `Dynamic DAST request failed for ${target}: ${error.message}`,
        'Ensure the localhost/staging target is running and reachable, then rerun Rock House with DAST enabled.',
        'Ouro'
      );
      gates.push({
        id: 'H6',
        status: 'UNKNOWN',
        evidence: target,
        note: `Dynamic request failed: ${error.message}`
      });
    }
  }

  return {
    configured: true,
    executed,
    url: baseUrl.toString(),
    paths
  };
}

function normalizePaths(paths) {
  const values = Array.isArray(paths) && paths.length > 0 ? paths : DEFAULT_PATHS;
  return values.map((value) => {
    const raw = String(value || '').trim();
    if (!raw) return '/';
    return raw.startsWith('/') ? raw : `/${raw}`;
  });
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`timed out after ${timeoutMs}ms`)), timeoutMs);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'user-agent': 'rock-house-dast/0.1'
      }
    });
  } finally {
    clearTimeout(timeout);
  }
}

function inspectResponse(options) {
  const {
    url,
    isPrimary,
    response,
    body,
    addFinding,
    gates
  } = options;
  const headers = lowerCaseHeaders(response.headers);

  if (isPrimary) {
    if (!headers['content-security-policy']) {
      addFinding('Medio', 'H1', 'Headers & CORS', url, 1, 'Dynamic response is missing Content-Security-Policy.', 'Add a restrictive Content-Security-Policy header on the deployed app.');
    }

    if (url.startsWith('https://') && !headers['strict-transport-security']) {
      addFinding('Medio', 'H2', 'Headers & CORS', url, 1, 'Dynamic HTTPS response is missing Strict-Transport-Security.', 'Add an HSTS header with a reviewed max-age and includeSubDomains when appropriate.');
    }

    if ((headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
      addFinding('Baixo', 'H3', 'Headers & CORS', url, 1, 'Dynamic response is missing X-Content-Type-Options: nosniff.', 'Add the X-Content-Type-Options header with value nosniff.');
    }

    if (headers.server || headers['x-powered-by']) {
      addFinding('Baixo', 'H5', 'Headers & CORS', url, 1, 'Dynamic response exposes server implementation details in headers.', 'Remove or minimize Server/X-Powered-By disclosure in production responses.');
    }
  }

  const origin = headers['access-control-allow-origin'];
  const credentials = (headers['access-control-allow-credentials'] || '').toLowerCase();
  if (origin === '*' && credentials === 'true') {
    addFinding('Critico', 'H4', 'Headers & CORS', url, 1, 'Dynamic response allows wildcard CORS together with credentials.', 'Replace wildcard CORS with an explicit allowlist and review credentialed cross-origin access.');
  } else if (origin === '*') {
    addFinding('Alto', 'H4', 'Headers & CORS', url, 1, 'Dynamic response allows wildcard CORS.', 'Replace wildcard CORS with an explicit origin allowlist.');
  } else if (credentials === 'true') {
    gates.push({
      id: 'H4',
      status: 'WARN',
      evidence: url,
      note: 'Credentialed CORS is enabled; verify the allowlist is explicit and reviewed.'
    });
  }

  if (response.status >= 500 && STACK_PATTERNS.some((pattern) => pattern.test(body))) {
    addFinding('Alto', 'S7', 'Secrets', url, 1, 'Dynamic error response appears to expose stack trace details.', 'Hide stack traces from client responses and keep detailed errors only in internal logs.');
  }
}

function lowerCaseHeaders(headers) {
  const result = {};
  headers.forEach((value, key) => {
    result[String(key).toLowerCase()] = String(value);
  });
  return result;
}

module.exports = {
  runDast
};
