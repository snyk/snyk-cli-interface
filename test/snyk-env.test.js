'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { restoreSystemEnv, cleanSnykEnv } = require('../snyk-env');
const indexExports = require('../index');

const PAIRS = [
  ['SNYK_SYSTEM_HTTP_PROXY', 'HTTP_PROXY'],
  ['SNYK_SYSTEM_HTTPS_PROXY', 'HTTPS_PROXY'],
  ['SNYK_SYSTEM_NO_PROXY', 'NO_PROXY'],
  ['SNYK_SYSTEM_OPENSSL_CONF', 'OPENSSL_CONF'],
];

// restoreSystemEnv

for (const [systemKey, targetKey] of PAIRS) {
  test(`restoreSystemEnv restores ${targetKey} from ${systemKey} and keeps the SNYK_* key`, () => {
    const env = { [targetKey]: 'internal', [systemKey]: 'user-value' };

    const result = restoreSystemEnv(env);

    assert.deepEqual(result, { [targetKey]: 'user-value', [systemKey]: 'user-value' });
  });

  test(`restoreSystemEnv deletes ${targetKey} when ${systemKey} is an empty string`, () => {
    const env = { [targetKey]: 'internal', [systemKey]: '' };

    const result = restoreSystemEnv(env);

    assert.equal(targetKey in result, false);
    assert.equal(result[systemKey], '');
  });

  test(`restoreSystemEnv leaves ${targetKey} alone when ${systemKey} is undefined`, () => {
    const env = { [targetKey]: 'internal', PATH: '/usr/bin' };

    const result = restoreSystemEnv(env);

    assert.deepEqual(result, { [targetKey]: 'internal', PATH: '/usr/bin' });
  });

  test(`restoreSystemEnv does not add ${targetKey} when neither it nor ${systemKey} is set`, () => {
    const result = restoreSystemEnv({ PATH: '/usr/bin' });

    assert.equal(targetKey in result, false);
  });
}

test('restoreSystemEnv deletes a target that is absent when the system value is empty', () => {
  const result = restoreSystemEnv({ SNYK_SYSTEM_NO_PROXY: '' });

  assert.equal('NO_PROXY' in result, false);
});

test('restoreSystemEnv uses env as systemEnv when it is not given', () => {
  const result = restoreSystemEnv({ HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'corp' });

  assert.equal(result.HTTP_PROXY, 'corp');
});

test('restoreSystemEnv reads SNYK_SYSTEM_* values from systemEnv, not env, when both are given', () => {
  const env = { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'from-env' };
  const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'from-system' };

  const result = restoreSystemEnv(env, systemEnv);

  assert.equal(result.HTTP_PROXY, 'from-system');
});

test('restoreSystemEnv ignores a SNYK_SYSTEM_* value present only in env when systemEnv is given', () => {
  const env = { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'from-env' };

  const result = restoreSystemEnv(env, {});

  assert.equal(result.HTTP_PROXY, 'internal');
});

test('restoreSystemEnv keeps SNYK_TOKEN, SNYK_API and SNYK_SYSTEM_* keys', () => {
  const env = {
    SNYK_TOKEN: 'token',
    SNYK_API: 'https://api.snyk.io',
    SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
    SNYK_SYSTEM_NO_PROXY: 'localhost',
  };

  const result = restoreSystemEnv(env);

  assert.deepEqual(result, {
    SNYK_TOKEN: 'token',
    SNYK_API: 'https://api.snyk.io',
    SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
    SNYK_SYSTEM_NO_PROXY: 'localhost',
    HTTP_PROXY: 'http://corp:3128',
    NO_PROXY: 'localhost',
  });
});

test('restoreSystemEnv copies none of the other keys of systemEnv', () => {
  const env = { PATH: '/usr/bin' };
  const systemEnv = {
    SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
    HTTPS_PROXY: 'http://not-a-system-value:1',
    SNYK_TOKEN: 'token',
    FOO: 'bar',
  };

  const result = restoreSystemEnv(env, systemEnv);

  assert.deepEqual(result, { PATH: '/usr/bin', HTTP_PROXY: 'http://corp:3128' });
});

test('restoreSystemEnv does not mutate either input and returns a new object', () => {
  const env = {
    PATH: '/usr/bin',
    HTTP_PROXY: 'internal',
    SNYK_TOKEN: 'token',
    SNYK_SYSTEM_HTTP_PROXY: 'corp',
    SNYK_SYSTEM_NO_PROXY: '',
    NO_PROXY: 'internal',
  };
  const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp', SNYK_SYSTEM_NO_PROXY: '' };
  const envCopy = { ...env };
  const systemEnvCopy = { ...systemEnv };

  const result = restoreSystemEnv(env, systemEnv);

  assert.deepEqual(env, envCopy);
  assert.deepEqual(systemEnv, systemEnvCopy);
  assert.notEqual(result, env);
  assert.notEqual(result, systemEnv);
});

// cleanSnykEnv

test('cleanSnykEnv removes SNYK_* variables case-insensitively, including SNYK_SYSTEM_*', () => {
  const env = {
    PATH: '/usr/bin',
    SNYK_TOKEN: 'token',
    SNYK_OAUTH_TOKEN: 'oauth',
    SNYK_CFG_API: 'https://api.snyk.io',
    snyk_token: 'lower',
    Snyk_Token: 'mixed',
    SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
    SNYK_SYSTEM_OPENSSL_CONF: '/etc/corp.cnf',
  };

  const result = cleanSnykEnv(env);

  assert.deepEqual(result, {
    PATH: '/usr/bin',
    HTTP_PROXY: 'http://corp:3128',
    OPENSSL_CONF: '/etc/corp.cnf',
  });
});

test('cleanSnykEnv keeps MY_SNYK_THING, http_proxy and PATH', () => {
  const env = {
    PATH: '/usr/bin',
    http_proxy: 'http://lower-proxy:8080',
    MY_SNYK_THING: 'keep-me',
    SNYK_TOKEN: 'token',
  };

  const result = cleanSnykEnv(env);

  assert.deepEqual(result, {
    PATH: '/usr/bin',
    http_proxy: 'http://lower-proxy:8080',
    MY_SNYK_THING: 'keep-me',
  });
});

test('cleanSnykEnv restores the proxy and OpenSSL pairs before removing SNYK_* keys', () => {
  const env = {
    HTTP_PROXY: 'internal',
    HTTPS_PROXY: 'internal',
    NO_PROXY: 'internal',
    OPENSSL_CONF: 'internal.cnf',
    SNYK_SYSTEM_HTTP_PROXY: 'corp:3128',
    SNYK_SYSTEM_HTTPS_PROXY: 'corp:3129',
    SNYK_SYSTEM_NO_PROXY: 'localhost',
    SNYK_SYSTEM_OPENSSL_CONF: '/etc/corp.cnf',
  };

  const result = cleanSnykEnv(env);

  assert.deepEqual(result, {
    HTTP_PROXY: 'corp:3128',
    HTTPS_PROXY: 'corp:3129',
    NO_PROXY: 'localhost',
    OPENSSL_CONF: '/etc/corp.cnf',
  });
});

test('cleanSnykEnv deletes a proxy target when its SNYK_SYSTEM_* value is an empty string', () => {
  const env = { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: '', SNYK_TOKEN: 'token' };

  const result = cleanSnykEnv(env);

  assert.deepEqual(result, {});
});

test('cleanSnykEnv deletes OPENSSL_CONF when SNYK_SYSTEM_OPENSSL_CONF is an empty string', () => {
  const env = { OPENSSL_CONF: 'internal.cnf', SNYK_SYSTEM_OPENSSL_CONF: '' };

  const result = cleanSnykEnv(env);

  assert.equal('OPENSSL_CONF' in result, false);
});

test('cleanSnykEnv leaves a proxy target alone when its SNYK_SYSTEM_* value is undefined', () => {
  const result = cleanSnykEnv({ HTTP_PROXY: 'internal', SNYK_TOKEN: 'token' });

  assert.deepEqual(result, { HTTP_PROXY: 'internal' });
});

test('cleanSnykEnv reads SNYK_SYSTEM_* values from systemEnv, not env, when both are given', () => {
  const env = { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'from-env' };
  const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'from-system' };

  const result = cleanSnykEnv(env, systemEnv);

  assert.deepEqual(result, { HTTP_PROXY: 'from-system' });
});

test('cleanSnykEnv never copies extra keys of systemEnv', () => {
  const env = { PATH: '/usr/bin' };
  const systemEnv = {
    SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
    SNYK_TOKEN: 'token',
    FOO: 'bar',
  };

  const result = cleanSnykEnv(env, systemEnv);

  assert.deepEqual(result, { PATH: '/usr/bin', HTTP_PROXY: 'http://corp:3128' });
});

test('cleanSnykEnv does not mutate either input and returns a new object', () => {
  const env = {
    PATH: '/usr/bin',
    HTTP_PROXY: 'internal',
    SNYK_TOKEN: 'token',
    SNYK_SYSTEM_HTTP_PROXY: 'corp',
  };
  const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp', SNYK_SYSTEM_NO_PROXY: 'localhost' };
  const envCopy = { ...env };
  const systemEnvCopy = { ...systemEnv };

  const result = cleanSnykEnv(env, systemEnv);

  assert.deepEqual(env, envCopy);
  assert.deepEqual(systemEnv, systemEnvCopy);
  assert.notEqual(result, env);
});

test('cleanSnykEnv does not read process.env', () => {
  const name = 'SNYK_SYSTEM_NO_PROXY';
  const saved = process.env[name];
  process.env[name] = 'leaked-from-process-env';
  try {
    const result = cleanSnykEnv({ PATH: '/usr/bin' });

    assert.deepEqual(result, { PATH: '/usr/bin' });
  } finally {
    if (saved === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = saved;
    }
  }
});

// index exports

test('restoreSystemEnv and cleanSnykEnv are exported from the package index', () => {
  assert.equal(typeof indexExports.restoreSystemEnv, 'function');
  assert.equal(typeof indexExports.cleanSnykEnv, 'function');
  assert.equal(indexExports.restoreSystemEnv, restoreSystemEnv);
  assert.equal(indexExports.cleanSnykEnv, cleanSnykEnv);
});

test('legacy exports are still present and sanitizeChildProcessEnv is gone', () => {
  assert.equal(typeof indexExports.legacyPlugin, 'object');
  assert.equal(typeof indexExports.legacyMonitor, 'object');
  assert.equal(typeof indexExports.legacyCommon, 'object');
  assert.equal('sanitizeChildProcessEnv' in indexExports, false);
});
