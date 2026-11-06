export type ChildProcessEnv = { [key: string]: string | undefined };

const SNYK_VAR_PATTERN = /^SNYK_/i;

// Each SNYK_SYSTEM_* variable holds the user's own value of the variable it restores.
const SYSTEM_RESTORES: ReadonlyArray<[string, string]> = [
  ['SNYK_SYSTEM_HTTP_PROXY', 'HTTP_PROXY'],
  ['SNYK_SYSTEM_HTTPS_PROXY', 'HTTPS_PROXY'],
  ['SNYK_SYSTEM_NO_PROXY', 'NO_PROXY'],
  ['SNYK_SYSTEM_OPENSSL_CONF', 'OPENSSL_CONF'],
];

/**
 * Undo the Snyk CLI's proxy and OpenSSL overrides, keeping SNYK_* variables.
 * For Snyk's own child processes.
 */
export function restoreSystemEnv(
  env: ChildProcessEnv,
  systemEnv: ChildProcessEnv = env,
): ChildProcessEnv {
  const result: ChildProcessEnv = { ...env };

  for (const [systemKey, targetKey] of SYSTEM_RESTORES) {
    const value = systemEnv[systemKey];
    if (value === undefined) {
      continue;
    }
    if (value === '') {
      delete result[targetKey];
    } else {
      result[targetKey] = value;
    }
  }

  return result;
}

/**
 * Env for third-party child processes: the user's own proxy and OpenSSL config, and no
 * SNYK_* variables. Pass `process.env` as `systemEnv` when `env` was built from a
 * caller-supplied object.
 */
export function cleanSnykEnv(
  env: ChildProcessEnv,
  systemEnv: ChildProcessEnv = env,
): ChildProcessEnv {
  const result = restoreSystemEnv(env, systemEnv);

  for (const key of Object.keys(result)) {
    if (SNYK_VAR_PATTERN.test(key)) {
      delete result[key];
    }
  }

  return result;
}
