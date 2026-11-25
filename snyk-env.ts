export type ChildProcessEnv = { [key: string]: string | undefined };

export interface SnykEnvOptions {
  /**
   * Writes HTTP_PROXY, HTTPS_PROXY and NO_PROXY from their SNYK_SYSTEM_* values, "" included.
   * `lowercase` also copies the restored values to their lowercase names.
   * `removeIfEmpty` removes a variable whose saved value is "" instead of writing "".
   * Other casings, such as Http_Proxy, stay as they are. On Windows the child may see either value.
   */
  restoreProxy?: boolean | { lowercase?: boolean; removeIfEmpty?: boolean };
  /** Writes OPENSSL_CONF from SNYK_SYSTEM_OPENSSL_CONF, "" included. */
  restoreOpenSSLConf?: boolean;
  /**
   * Removes every SNYK_* variable (any casing). Defaults to true. With false, nothing is removed,
   * which Snyk's own child processes, such as the nested Go CLI, need to keep their token and config.
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
 * `systemEnv` is where SNYK_SYSTEM_* values are read from, normally `process.env`. They are not
 * read from `env`. If a saved value is missing from `systemEnv`, the variable stays as it is.
 */
export function cleanSnykEnv(
  env: ChildProcessEnv,
  systemEnv: ChildProcessEnv,
  options: SnykEnvOptions = {},
): ChildProcessEnv {
  const result: ChildProcessEnv = { ...env };

  if (options.restoreProxy) {
    const proxy: { lowercase?: boolean; removeIfEmpty?: boolean } =
      typeof options.restoreProxy === 'object' ? options.restoreProxy : {};
    for (const name of PROXY_NAMES) {
      const saved = systemEnv['SNYK_SYSTEM_' + name];
      if (saved === undefined) {
        continue;
      }
      if (saved === '' && proxy.removeIfEmpty) {
        delete result[name];
      } else {
        result[name] = saved;
      }
    }
    if (proxy.lowercase) {
      for (const name of PROXY_NAMES) {
        if (result[name] !== undefined) {
          result[name.toLowerCase()] = result[name];
        }
      }
    }
  }
  if (options.restoreOpenSSLConf) {
    restoreFromSystemEnv(result, systemEnv, OPENSSL_CONF);
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
