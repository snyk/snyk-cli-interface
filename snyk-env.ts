export type ChildProcessEnv = { [key: string]: string | undefined };

const SNYK_VAR_PATTERN = /^SNYK_/i;

// This list must match the variables the Go CLI saves as SNYK_SYSTEM_* in snyk/cli
// cliv2/internal/cliv2/cliv2.go ("preserve original proxy settings"). Add a variable there, add it here too.
// Each SNYK_SYSTEM_* variable holds the user's own value of the variable it restores.
// The flag marks targets that also get an all-lowercase copy. OPENSSL_CONF has no lowercase convention.
const SYSTEM_RESTORES: ReadonlyArray<[string, string, boolean]> = [
  ['SNYK_SYSTEM_HTTP_PROXY', 'HTTP_PROXY', true],
  ['SNYK_SYSTEM_HTTPS_PROXY', 'HTTPS_PROXY', true],
  ['SNYK_SYSTEM_NO_PROXY', 'NO_PROXY', true],
  ['SNYK_SYSTEM_OPENSSL_CONF', 'OPENSSL_CONF', false],
];

/**
 * Returns a copy of `env` with the user's own proxy and OpenSSL settings restored.
 * SNYK_* variables are kept, so use this for Snyk's own child processes.
 *
 * The CLI replaces HTTP_PROXY, HTTPS_PROXY, NO_PROXY and OPENSSL_CONF, and saves the
 * user's values as SNYK_SYSTEM_<name>. Each saved value is read from `systemEnv`.
 * For HTTP_PROXY, HTTPS_PROXY and NO_PROXY, every casing of the name is removed and the
 * value is written under both the uppercase and the all-lowercase name. An empty value
 * leaves both deleted. OPENSSL_CONF is written under its uppercase name only.
 * A missing saved value changes nothing.
 *
 * `systemEnv` is where the SNYK_SYSTEM_* values are read from, normally `process.env`.
 */
export function restoreSystemEnv(
  env: ChildProcessEnv,
  systemEnv: ChildProcessEnv,
): ChildProcessEnv {
  const result: ChildProcessEnv = { ...env };

  for (const [systemKey, targetKey, withLowercase] of SYSTEM_RESTORES) {
    const value = systemEnv[systemKey];
    if (value === undefined) {
      continue;
    }
    // Env names are case-insensitive on Windows, so drop every casing of the target first.
    for (const key of Object.keys(result)) {
      if (key.toUpperCase() === targetKey) {
        delete result[key];
      }
    }
    if (value !== '') {
      result[targetKey] = value;
      // curl, and so git, reads only lowercase http_proxy for http:// URLs, and some tools
      // read only one casing of the others, so write both. Windows picks either casing;
      // both hold the same value, so the pick does not matter.
      if (withLowercase) {
        result[targetKey.toLowerCase()] = value;
      }
    }
  }

  return result;
}

/**
 * Returns a copy of `env` that is safe for third-party child processes such as build
 * tools. It calls restoreSystemEnv to restore the user's own proxy and OpenSSL settings,
 * then removes every SNYK_* variable (any casing), so no Snyk credentials reach the child.
 *
 * `systemEnv` is where the SNYK_SYSTEM_* values are read from, normally `process.env`.
 */
export function cleanSnykEnv(
  env: ChildProcessEnv,
  systemEnv: ChildProcessEnv,
): ChildProcessEnv {
  const result = restoreSystemEnv(env, systemEnv);

  for (const key of Object.keys(result)) {
    if (SNYK_VAR_PATTERN.test(key)) {
      delete result[key];
    }
  }

  return result;
}
