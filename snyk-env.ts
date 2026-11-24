export type ChildProcessEnv = { [key: string]: string | undefined };

export interface SnykEnvOptions {
  /** Writes HTTP_PROXY, HTTPS_PROXY and NO_PROXY from their SNYK_SYSTEM_* values, "" included. */
  restoreProxy?: boolean;
  /**
   * Copies HTTP_PROXY, HTTPS_PROXY and NO_PROXY to their lowercase names. Without restoreProxy,
   * that copies the CLI's internal proxy URL.
   */
  lowercaseProxy?: boolean;
  /** Writes OPENSSL_CONF from SNYK_SYSTEM_OPENSSL_CONF, "" included. */
  restoreOpenSSLConf?: boolean;
  /**
   * Removes every SNYK_* variable (any casing). Defaults to true. Snyk's own child processes,
   * such as the nested Go CLI, pass false to keep their token and config.
   */
  removeSnykVars?: boolean;
}

const SNYK_VAR_PATTERN = /^SNYK_/i;

// These names must match the variables the Go CLI saves as SNYK_SYSTEM_* in snyk/cli
// cliv2/internal/cliv2/cliv2.go ("preserve original proxy settings"). Add a variable there, add it here too.
const PROXY_NAMES: ReadonlyArray<string> = ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'];
const OPENSSL_CONF = 'OPENSSL_CONF';

function restoreFromSystemEnv(result: ChildProcessEnv, systemEnv: ChildProcessEnv, name: string): void {
  const saved = systemEnv['SNYK_SYSTEM_' + name];
  if (saved !== undefined) {
    result[name] = saved;
  }
}

/**
 * Returns a copy of `env` with the given options applied, then SNYK_* variables (any casing)
 * removed unless `removeSnykVars` is false. Pass no options to remove SNYK_* only.
 * `systemEnv` is where SNYK_SYSTEM_* values are read from, normally `process.env`.
 */
export function cleanSnykEnv(
  env: ChildProcessEnv,
  systemEnv: ChildProcessEnv,
  options: SnykEnvOptions = {},
): ChildProcessEnv {
  const result: ChildProcessEnv = { ...env };

  if (options.restoreProxy) {
    for (const name of PROXY_NAMES) {
      restoreFromSystemEnv(result, systemEnv, name);
    }
  }
  if (options.restoreOpenSSLConf) {
    restoreFromSystemEnv(result, systemEnv, OPENSSL_CONF);
  }
  if (options.lowercaseProxy) {
    for (const name of PROXY_NAMES) {
      if (result[name] !== undefined) {
        result[name.toLowerCase()] = result[name];
      }
    }
  }
  if (options.removeSnykVars !== false) {
    for (const key of Object.keys(result)) {
      if (SNYK_VAR_PATTERN.test(key)) {
        delete result[key];
      }
    }
  }

  return result;
}
