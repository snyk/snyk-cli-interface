'use strict';

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

const { restoreSystemEnv, cleanSnykEnv } = require('../snyk-env');
const indexExports = require('../index');

describe('restoreSystemEnv', () => {
  const proxyRows = [
    { name: 'saved value set, target absent: uppercase and lowercase target added',
      env: { SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { HTTP_PROXY: 'corp', http_proxy: 'corp', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
    },
    { name: 'saved value set, uppercase target present: both casings replaced',
      env: { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { HTTP_PROXY: 'corp', http_proxy: 'corp', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
    },
    { name: 'saved value set, mixed-case targets: only uppercase and lowercase remain',
      env: { http_proxy: 'a', Http_Proxy: 'b', HTTP_PROXY: 'c', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { HTTP_PROXY: 'corp', http_proxy: 'corp', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
    },
    { name: 'empty saved value for lowercase-only target: neither casing present',
      env: { http_proxy: 'a', SNYK_SYSTEM_HTTP_PROXY: '' },
      expected: { SNYK_SYSTEM_HTTP_PROXY: '' },
    },
    { name: 'OPENSSL_CONF: only uppercase written, lowercase variants removed',
      env: { OPENSSL_CONF: 'internal', openssl_conf: 'x', SNYK_SYSTEM_OPENSSL_CONF: '/etc/ssl/corp.cnf' },
      expected: { OPENSSL_CONF: '/etc/ssl/corp.cnf', SNYK_SYSTEM_OPENSSL_CONF: '/etc/ssl/corp.cnf' },
    },
    { name: 'empty saved value, target in several casings: all removed',
      env: { HTTP_PROXY: 'a', http_proxy: 'b', Http_Proxy: 'c', SNYK_SYSTEM_HTTP_PROXY: '' },
      expected: { SNYK_SYSTEM_HTTP_PROXY: '' },
    },
    { name: 'empty saved value, target absent: nothing added',
      env: { SNYK_SYSTEM_HTTP_PROXY: '' },
      expected: { SNYK_SYSTEM_HTTP_PROXY: '' },
    },
    { name: 'saved value undefined: target casings unchanged',
      env: { HTTP_PROXY: 'a', http_proxy: 'b' },
      expected: { HTTP_PROXY: 'a', http_proxy: 'b' },
    },
    { name: 'lowercase snyk_system_http_proxy is ignored',
      env: { HTTP_PROXY: 'a', snyk_system_http_proxy: 'corp' },
      expected: { HTTP_PROXY: 'a', snyk_system_http_proxy: 'corp' },
    },
  ];

  for (const row of proxyRows) {
    test(row.name, () => {
      assert.deepEqual(restoreSystemEnv(row.env, row.env), row.expected);
    });
  }

  // Each lowercase-capable target: only lowercase originally, and both casings originally.
  for (const [target, systemKey] of [
    ['HTTP_PROXY', 'SNYK_SYSTEM_HTTP_PROXY'],
    ['HTTPS_PROXY', 'SNYK_SYSTEM_HTTPS_PROXY'],
    ['NO_PROXY', 'SNYK_SYSTEM_NO_PROXY'],
  ]) {
    const lower = target.toLowerCase();
    const mixed = target[0] + target.slice(1).toLowerCase();

    test(`${target}: only ${lower} originally, both casings written`, () => {
      const env = { [target]: 'internal', [systemKey]: 'user' };

      assert.deepEqual(
        restoreSystemEnv(env, env),
        { [target]: 'user', [lower]: 'user', [systemKey]: 'user' },
      );
    });

    test(`${target}: both casings originally, both equal saved, other casing gone`, () => {
      const env = { [target]: 'internal', [lower]: 'user', [mixed]: 'x', [systemKey]: 'user' };

      assert.deepEqual(
        restoreSystemEnv(env, env),
        { [target]: 'user', [lower]: 'user', [systemKey]: 'user' },
      );
    });
  }

  test('restores all four pairs, including a lowercase no_proxy', () => {
    const env = {
      HTTP_PROXY: 'a', HTTPS_PROXY: 'b', no_proxy: 'c', OPENSSL_CONF: 'd',
      SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
      SNYK_SYSTEM_HTTPS_PROXY: 'https://corp:3129',
      SNYK_SYSTEM_NO_PROXY: 'localhost',
      SNYK_SYSTEM_OPENSSL_CONF: '/etc/ssl/corp.cnf',
    };

    assert.deepEqual(restoreSystemEnv(env, env), {
      HTTP_PROXY: 'http://corp:3128',
      http_proxy: 'http://corp:3128',
      HTTPS_PROXY: 'https://corp:3129',
      https_proxy: 'https://corp:3129',
      NO_PROXY: 'localhost',
      no_proxy: 'localhost',
      OPENSSL_CONF: '/etc/ssl/corp.cnf',
      SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
      SNYK_SYSTEM_HTTPS_PROXY: 'https://corp:3129',
      SNYK_SYSTEM_NO_PROXY: 'localhost',
      SNYK_SYSTEM_OPENSSL_CONF: '/etc/ssl/corp.cnf',
    });
  });

  test('changes only the targets of the one system key that is set', () => {
    const env = { HTTP_PROXY: 'a', HTTPS_PROXY: 'b', NO_PROXY: 'c', OPENSSL_CONF: 'd', SNYK_SYSTEM_NO_PROXY: 'localhost' };

    assert.deepEqual(restoreSystemEnv(env, env), {
      HTTP_PROXY: 'a', HTTPS_PROXY: 'b', NO_PROXY: 'localhost', no_proxy: 'localhost', OPENSSL_CONF: 'd', SNYK_SYSTEM_NO_PROXY: 'localhost',
    });
  });

  const systemEnvRows = [
    { name: 'takes the saved value from systemEnv, not env',
      env: { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'env-value' },
      systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { HTTP_PROXY: 'corp', http_proxy: 'corp', SNYK_SYSTEM_HTTP_PROXY: 'env-value' },
    },
    { name: 'ignores a saved value that only env has when systemEnv is given',
      env: { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'env-value' },
      systemEnv: {},
      expected: { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'env-value' },
    },
    { name: 'copies no other keys from systemEnv',
      env: { PATH: '/usr/bin', HTTP_PROXY: 'internal' },
      systemEnv: { PATH: '/sys', SNYK_TOKEN: 't', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { PATH: '/usr/bin', HTTP_PROXY: 'corp', http_proxy: 'corp' },
    },
  ];

  for (const row of systemEnvRows) {
    test(row.name, () => {
      assert.deepEqual(restoreSystemEnv(row.env, row.systemEnv), row.expected);
    });
  }

  test('keeps SNYK_* keys and unrelated keys', () => {
    const env = {
      PATH: '/usr/bin', SNYK_TOKEN: 't', snyk_token: 't', SNYK_API: 'https://api.snyk.io',
      SNYK_SYSTEM_NO_PROXY: 'localhost',
    };

    assert.deepEqual(restoreSystemEnv(env, env), { ...env, NO_PROXY: 'localhost', no_proxy: 'localhost' });
  });

  test('returns a new object and mutates neither input', () => {
    const env = { Http_Proxy: 'a', http_proxy: 'b', HTTP_PROXY: 'c', SNYK_SYSTEM_HTTP_PROXY: 'corp' };
    const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp' };
    const envBefore = { ...env };
    const systemEnvBefore = { ...systemEnv };

    const result = restoreSystemEnv(env, systemEnv);

    assert.notEqual(result, env);
    assert.deepEqual(env, envBefore);
    assert.deepEqual(systemEnv, systemEnvBefore);
  });
});

describe('cleanSnykEnv', () => {
  for (const name of ['SNYK_TOKEN', 'snyk_token', 'Snyk_Token', 'SNYK_OAUTH_TOKEN', 'SNYK_']) {
    test(`removes ${name}`, () => {
      const env = { PATH: '/usr/bin', [name]: 'v' };

      assert.deepEqual(cleanSnykEnv(env, env), { PATH: '/usr/bin' });
    });
  }

  test('removes SNYK_SYSTEM_HTTP_PROXY and restores HTTP_PROXY and http_proxy from it', () => {
    const env = { SNYK_SYSTEM_HTTP_PROXY: 'corp' };

    assert.deepEqual(cleanSnykEnv(env, env), { HTTP_PROXY: 'corp', http_proxy: 'corp' });
  });

  test('only lowercase http_proxy originally: both casings restored, SNYK_* removed', () => {
    const env = { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'user', SNYK_TOKEN: 't' };

    assert.deepEqual(cleanSnykEnv(env, env), { HTTP_PROXY: 'user', http_proxy: 'user' });
  });

  test('keeps MY_SNYK_THING, XSNYK_TOKEN, PATH and http_proxy without a saved value', () => {
    const env = { PATH: '/usr/bin', MY_SNYK_THING: 'x', XSNYK_TOKEN: 'x', http_proxy: 'x' };

    assert.deepEqual(cleanSnykEnv(env, env), env);
  });

  test('restores user proxy values, then removes every SNYK_* key', () => {
    const env = {
      PATH: '/usr/bin', SNYK_TOKEN: 't',
      HTTP_PROXY: 'internal', Http_Proxy: 'internal-mixed', HTTPS_PROXY: 'internal',
      NO_PROXY: 'internal', OPENSSL_CONF: 'internal',
      SNYK_SYSTEM_HTTP_PROXY: 'http://corp:3128',
      SNYK_SYSTEM_HTTPS_PROXY: 'https://corp:3129',
      SNYK_SYSTEM_NO_PROXY: '',
      SNYK_SYSTEM_OPENSSL_CONF: '/etc/ssl/corp.cnf',
    };

    assert.deepEqual(cleanSnykEnv(env, env), {
      PATH: '/usr/bin',
      HTTP_PROXY: 'http://corp:3128',
      http_proxy: 'http://corp:3128',
      HTTPS_PROXY: 'https://corp:3129',
      https_proxy: 'https://corp:3129',
      OPENSSL_CONF: '/etc/ssl/corp.cnf',
    });
  });

  test('restores from systemEnv when it is given', () => {
    const env = { PATH: '/usr/bin', HTTP_PROXY: 'internal' };
    const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp', SNYK_TOKEN: 't' };

    assert.deepEqual(cleanSnykEnv(env, systemEnv), { PATH: '/usr/bin', HTTP_PROXY: 'corp', http_proxy: 'corp' });
  });

  test('returns a new object and mutates neither input', () => {
    const env = { PATH: '/usr/bin', SNYK_TOKEN: 't', Http_Proxy: 'a', SNYK_SYSTEM_HTTP_PROXY: 'corp' };
    const systemEnv = { SNYK_SYSTEM_NO_PROXY: 'localhost' };
    const envBefore = { ...env };
    const systemEnvBefore = { ...systemEnv };

    const result = cleanSnykEnv(env, systemEnv);

    assert.notEqual(result, env);
    assert.deepEqual(env, envBefore);
    assert.deepEqual(systemEnv, systemEnvBefore);
  });

  test('does not read process.env', () => {
    const key = 'SNYK_SYSTEM_HTTP_PROXY';
    const original = process.env[key];
    process.env[key] = 'from-process-env';

    try {
      const env = { PATH: '/usr/bin' };

      assert.deepEqual(cleanSnykEnv(env, env), { PATH: '/usr/bin' });
      assert.deepEqual(restoreSystemEnv(env, env), { PATH: '/usr/bin' });
    } finally {
      if (original === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = original;
      }
    }
  });

  // This is the test that gives the Windows CI job something Windows-specific to check:
  // process.env is case-insensitive there, and spawn keeps only one casing of a duplicated name.
  test('child process receives the user\'s proxy and no SNYK_* variables (real spawn)', () => {
    // Copy the real env so the child can start on Windows (SystemRoot, PATH, ...),
    // then drop every proxy and SNYK_* key so the result does not depend on the machine.
    const env = { ...process.env };
    for (const key of Object.keys(env)) {
      if (/^(HTTP_PROXY|HTTPS_PROXY|NO_PROXY)$/i.test(key) || /^SNYK_/i.test(key)) {
        delete env[key];
      }
    }

    // What the Go CLI hands the TS CLI.
    env.HTTP_PROXY = 'http://snyk:secret-proxy-pw@127.0.0.1:1234';
    env.HTTPS_PROXY = 'http://snyk:secret-proxy-pw@127.0.0.1:1234';
    env.http_proxy = 'http://user-proxy:3128';
    env.SNYK_SYSTEM_HTTP_PROXY = 'http://user-proxy:3128';
    env.SNYK_SYSTEM_HTTPS_PROXY = 'http://user-proxy:3128';
    env.SNYK_SYSTEM_NO_PROXY = 'localhost';
    env.SNYK_TOKEN = 'tok-secret-value';
    env.snyk_oauth_token = 'oauth-secret-value';

    const childEnv = cleanSnykEnv(env, env);
    const script =
      'process.stdout.write(JSON.stringify({ env: process.env, ' +
      'http: process.env.http_proxy, HTTP: process.env.HTTP_PROXY, ' +
      'https: process.env.https_proxy, HTTPS: process.env.HTTPS_PROXY, ' +
      'no: process.env.no_proxy, NO: process.env.NO_PROXY }))';
    const result = spawnSync(process.execPath, ['-e', script], { env: childEnv, encoding: 'utf8', timeout: 30000 });

    assert.equal(result.status, 0, result.stderr || String(result.error));

    const out = JSON.parse(result.stdout);
    const userProxy = 'http://user-proxy:3128';
    assert.equal(out.http, userProxy);
    assert.equal(out.HTTP, userProxy);
    assert.equal(out.https, userProxy);
    assert.equal(out.HTTPS, userProxy);
    assert.equal(out.no, 'localhost');
    assert.equal(out.NO, 'localhost');
    for (const key of Object.keys(out.env)) {
      assert.doesNotMatch(key, /^snyk_/i);
    }
    assert.doesNotMatch(result.stdout, /secret-proxy-pw|tok-secret-value|oauth-secret-value/);
  });
});

describe('package exports', () => {
  test('exports cleanSnykEnv and restoreSystemEnv as functions', () => {
    assert.equal(typeof indexExports.cleanSnykEnv, 'function');
    assert.equal(typeof indexExports.restoreSystemEnv, 'function');
    assert.equal(indexExports.cleanSnykEnv, cleanSnykEnv);
    assert.equal(indexExports.restoreSystemEnv, restoreSystemEnv);
  });

  test('keeps legacy exports', () => {
    assert.equal(typeof indexExports.legacyPlugin, 'object');
    assert.equal(typeof indexExports.legacyMonitor, 'object');
    assert.equal(typeof indexExports.legacyCommon, 'object');
  });
});
