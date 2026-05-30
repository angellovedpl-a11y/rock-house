const DEFAULT_PATHS = ['/'];
const DEFAULT_REDIRECT_PARAM_NAMES = ['next', 'redirect', 'returnTo', 'url'];
const OPEN_REDIRECT_SENTINEL = 'https://evil.example/rock-house';
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

  const paths = normalizePaths(dast.paths, DEFAULT_PATHS);
  const authProtectedPaths = normalizePaths(dast.authProtectedPaths);
  const errorPaths = normalizePaths(dast.errorPaths);
  const redirectParamNames = normalizeNames(dast.redirectParamNames, DEFAULT_REDIRECT_PARAM_NAMES);
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

  for (const targetPath of authProtectedPaths) {
    const target = new URL(targetPath, baseUrl).toString();
    try {
      const response = await fetchWithTimeout(target, timeoutMs);
      executed = true;
      inspectProtectedRoute({ url: target, response, addFinding, gates });
    } catch (error) {
      addUnknown(
        'A4',
        'Auth & Access',
        `Protected-route probe failed for ${target}: ${error.message}`,
        'Ensure the localhost/staging target is reachable, then rerun Rock House with authProtectedPaths configured.',
        'Prata'
      );
    }
  }

  for (const targetPath of errorPaths) {
    const target = new URL(targetPath, baseUrl).toString();
    try {
      const response = await fetchWithTimeout(target, timeoutMs);
      executed = true;
      const body = await response.text();
      inspectErrorRoute({ url: target, response, body, addFinding, gates });
    } catch (error) {
      addUnknown(
        'S7',
        'Secrets',
        `Error-route probe failed for ${target}: ${error.message}`,
        'Ensure the localhost/staging target is reachable, then rerun Rock House with errorPaths configured.',
        'Prata'
      );
    }
  }

  for (const targetPath of paths) {
    for (const paramName of redirectParamNames) {
      const target = buildRedirectProbeUrl(baseUrl, targetPath, paramName);
      try {
        const response = await fetchWithTimeout(target, timeoutMs);
        executed = true;
        inspectRedirectProbe({ url: target, response, paramName, addFinding });
      } catch (error) {
        addUnknown(
          'H7',
          'Headers & CORS',
          `Redirect probe failed for ${target}: ${error.message}`,
          'Ensure the localhost/staging target is reachable, then rerun Rock House with redirectParamNames configured.',
          'Prata'
        );
      }
    }
  }

  return {
    configured: true,
    executed,
    url: baseUrl.toString(),
    paths,
    authProtectedPaths,
    errorPaths,
    redirectParamNames
  };
}

function normalizePaths(paths, fallback = []) {
  const values = Array.isArray(paths) && paths.length > 0 ? paths : fallback;
  return values.map((value) => {
    const raw = String(value || '').trim();
    if (!raw) return '/';
    return raw.startsWith('/') ? raw : `/${raw}`;
  });
}

function normalizeNames(values, fallback) {
  const chosen = Array.isArray(values) && values.length > 0 ? values : fallback;
  return chosen.map((value) => String(value || '').trim()).filter(Boolean);
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

function inspectProtectedRoute(options) {
  const { url, response, addFinding, gates } = options;
  if ([401, 403].includes(response.status)) {
    gates.push({
      id: 'A4',
      status: 'PASS',
      evidence: url,
      note: `Protected route returned ${response.status} without credentials.`
    });
    return;
  }

  if ([301, 302, 303, 307, 308].includes(response.status)) {
    gates.push({
      id: 'A4',
      status: 'PASS',
      evidence: url,
      note: `Protected route redirected unauthenticated client with ${response.status}.`
    });
    return;
  }

  addFinding('Critico', 'A4', 'Auth & Access', url, 1, 'Configured protected route responded without an authentication challenge.', 'Require authentication before serving this route, or remove it from authProtectedPaths if it is intentionally public.');
}

function inspectErrorRoute(options) {
  const { url, response, body, addFinding, gates } = options;
  if (response.status >= 500 && STACK_PATTERNS.some((pattern) => pattern.test(body))) {
    addFinding('Alto', 'S7', 'Secrets', url, 1, 'Dynamic error route appears to expose stack trace details.', 'Hide stack traces from error routes and keep details only in internal logs.');
    return;
  }

  gates.push({
    id: 'S7',
    status: 'PASS',
    evidence: url,
    note: `Error-route probe returned ${response.status} without stack disclosure.`
  });
}

function buildRedirectProbeUrl(baseUrl, targetPath, paramName) {
  const target = new URL(targetPath || '/', baseUrl);
  target.searchParams.set(paramName, OPEN_REDIRECT_SENTINEL);
  return target.toString();
}

function inspectRedirectProbe(options) {
  const { url, response, paramName, addFinding } = options;
  const location = response.headers.get('location') || '';
  if (location.startsWith(OPEN_REDIRECT_SENTINEL)) {
    addFinding('Alto', 'H7', 'Headers & CORS', url, 1, `Dynamic redirect probe reflected external ${paramName} target in Location header.`, 'Reject absolute external redirect targets or map them through a reviewed allowlist.');
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
