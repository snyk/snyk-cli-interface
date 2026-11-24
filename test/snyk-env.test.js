'use strict';

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

const { cleanSnykEnv } = require('../snyk-env');
const indexExports = require('../index');

const PROXY_NAMES = ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'];

describe('cleanSnykEnv default and removeSnykVars', () => {
  const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp', SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' };
  const rows = [
    { name: 'removes SNYK_TOKEN', env: { PATH: '/usr/bin', SNYK_TOKEN: 'v' }, expected: { PATH: '/usr/bin' } },
    { name: 'removes lowercase snyk_token', env: { snyk_token: 'v' }, expected: {} },
    { name: 'removes mixed-case Snyk_Token', env: { Snyk_Token: 'v' }, expected: {} },
    { name: 'keeps proxies and OPENSSL_CONF as the caller had them',
      env: { HTTP_PROXY: 'a', http_proxy: 'b', NO_PROXY: 'c', OPENSSL_CONF: 'd', SNYK_SYSTEM_HTTP_PROXY: 'x' },
      expected: { HTTP_PROXY: 'a', http_proxy: 'b', NO_PROXY: 'c', OPENSSL_CONF: 'd' } },
    { name: 'keeps names that only contain SNYK', env: { MY_SNYK_THING: 'x', XSNYK_TOKEN: 'x' },
      expected: { MY_SNYK_THING: 'x', XSNYK_TOKEN: 'x' } },
    { name: 'removeSnykVars: false keeps SNYK_* and restores nothing', options: { removeSnykVars: false },
      env: { PATH: '/usr/bin', HTTP_PROXY: 'a', SNYK_TOKEN: 't', snyk_token: 't', SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { PATH: '/usr/bin', HTTP_PROXY: 'a', SNYK_TOKEN: 't', snyk_token: 't', SNYK_SYSTEM_HTTP_PROXY: 'corp' } },
  ];

  for (const row of rows) {
    test(row.name, () => {
      assert.deepEqual(cleanSnykEnv(row.env, systemEnv, row.options), row.expected);
    });
  }
});

describe('restoreProxy', () => {
  const rows = [
    { name: 'writes the saved value when the target is absent',
      env: {}, systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' }, expected: { HTTP_PROXY: 'corp' } },
    { name: 'writes an empty saved value as "" over an existing target',
      env: { HTTP_PROXY: 'internal' }, systemEnv: { SNYK_SYSTEM_HTTP_PROXY: '' }, expected: { HTTP_PROXY: '' } },
    { name: 'writes an empty saved value as "" when the target is absent',
      env: {}, systemEnv: { SNYK_SYSTEM_HTTP_PROXY: '' }, expected: { HTTP_PROXY: '' } },
    { name: 'leaves an uppercase target alone when the saved value is undefined',
      env: { HTTP_PROXY: 'internal' }, systemEnv: {}, expected: { HTTP_PROXY: 'internal' } },
    { name: 'adds nothing when the saved value is undefined and the target is absent',
      env: {}, systemEnv: {}, expected: {} },
    { name: 'leaves a mixed-case target alone',
      env: { Http_Proxy: 'b' }, systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' }, expected: { Http_Proxy: 'b', HTTP_PROXY: 'corp' } },
    { name: 'reads the saved value from systemEnv, not env',
      env: { HTTP_PROXY: 'internal', SNYK_SYSTEM_HTTP_PROXY: 'env-value' },
      systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { HTTP_PROXY: 'corp', SNYK_SYSTEM_HTTP_PROXY: 'env-value' } },
    { name: 'ignores a lowercase snyk_system_ key',
      env: { HTTP_PROXY: 'a' }, systemEnv: { snyk_system_http_proxy: 'corp' }, expected: { HTTP_PROXY: 'a' } },
    { name: 'does not touch OPENSSL_CONF',
      env: { OPENSSL_CONF: 'internal' }, systemEnv: { SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' }, expected: { OPENSSL_CONF: 'internal' } },
  ];

  for (const name of PROXY_NAMES) {
    const lower = name.toLowerCase();
    const systemKey = `SNYK_SYSTEM_${name}`;
    rows.push(
      { name: `${name}: restored, lowercase ${lower} left alone`,
        env: { [name]: 'internal', [lower]: 'a' }, systemEnv: { [systemKey]: 'corp' },
        expected: { [name]: 'corp', [lower]: 'a' } },
    );
  }

  for (const row of rows) {
    test(row.name, () => {
      assert.deepEqual(cleanSnykEnv(row.env, row.systemEnv, { restoreProxy: true, removeSnykVars: false }), row.expected);
    });
  }
});

describe('restoreOpenSSLConf', () => {
  const rows = [
    { name: 'writes the saved value when the target is absent',
      env: {}, systemEnv: { SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' }, expected: { OPENSSL_CONF: '/corp.cnf' } },
    { name: 'overwrites an existing OPENSSL_CONF',
      env: { OPENSSL_CONF: 'internal' }, systemEnv: { SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' },
      expected: { OPENSSL_CONF: '/corp.cnf' } },
    { name: 'writes an empty saved value as ""',
      env: { OPENSSL_CONF: 'internal' }, systemEnv: { SNYK_SYSTEM_OPENSSL_CONF: '' }, expected: { OPENSSL_CONF: '' } },
    { name: 'leaves OPENSSL_CONF alone when the saved value is undefined',
      env: { OPENSSL_CONF: 'internal' }, systemEnv: {}, expected: { OPENSSL_CONF: 'internal' } },
    { name: 'leaves a lowercase openssl_conf alone',
      env: { openssl_conf: 'x' }, systemEnv: { SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' },
      expected: { openssl_conf: 'x', OPENSSL_CONF: '/corp.cnf' } },
    { name: 'does not restore proxies',
      env: { HTTP_PROXY: 'a' }, systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' }, expected: { HTTP_PROXY: 'a' } },
  ];

  for (const row of rows) {
    test(row.name, () => {
      assert.deepEqual(cleanSnykEnv(row.env, row.systemEnv, { restoreOpenSSLConf: true, removeSnykVars: false }), row.expected);
    });
  }
});

describe('lowercaseProxy', () => {
  const rows = [
    { name: 'copies an empty uppercase value as ""', env: { NO_PROXY: '' },
      expected: { NO_PROXY: '', no_proxy: '' } },
    { name: 'overwrites an existing lowercase value', env: { HTTPS_PROXY: 'internal', https_proxy: 'old' },
      expected: { HTTPS_PROXY: 'internal', https_proxy: 'internal' } },
    { name: 'leaves a lowercase value alone when the uppercase one is undefined', env: { http_proxy: 'a' },
      expected: { http_proxy: 'a' } },
    { name: 'leaves a mixed-case name alone', env: { Http_Proxy: 'b', HTTP_PROXY: 'a' },
      expected: { Http_Proxy: 'b', HTTP_PROXY: 'a', http_proxy: 'a' } },
    { name: 'does not copy OPENSSL_CONF', env: { OPENSSL_CONF: 'x' }, expected: { OPENSSL_CONF: 'x' } },
    { name: 'does not read SNYK_SYSTEM_* from systemEnv', env: {},
      systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' }, expected: {} },
  ];

  for (const name of PROXY_NAMES) {
    rows.push({ name: `copies ${name} to its lowercase name`,
      env: { [name]: 'internal' }, expected: { [name]: 'internal', [name.toLowerCase()]: 'internal' } });
  }

  for (const row of rows) {
    test(row.name, () => {
      assert.deepEqual(cleanSnykEnv(row.env, row.systemEnv || {}, { lowercaseProxy: true, removeSnykVars: false }), row.expected);
    });
  }
});

describe('restoreProxy combined with lowercaseProxy', () => {
  const rows = [
    { name: 'lowercase gets the restored value, not the caller value',
      env: { HTTP_PROXY: 'internal', http_proxy: 'old' }, systemEnv: { SNYK_SYSTEM_HTTP_PROXY: 'corp' },
      expected: { HTTP_PROXY: 'corp', http_proxy: 'corp' } },
    { name: 'empty saved value is written to both casings',
      env: { HTTPS_PROXY: 'internal' }, systemEnv: { SNYK_SYSTEM_HTTPS_PROXY: '' },
      expected: { HTTPS_PROXY: '', https_proxy: '' } },
    { name: 'uppercase and saved both undefined: lowercase left alone',
      env: { http_proxy: 'a' }, systemEnv: {}, expected: { http_proxy: 'a' } },
  ];

  for (const row of rows) {
    test(row.name, () => {
      assert.deepEqual(
        cleanSnykEnv(row.env, row.systemEnv || {}, { restoreProxy: true, lowercaseProxy: true, removeSnykVars: false }),
        row.expected,
      );
    });
  }
});

describe('go-bridge options', () => {
  test('restores HTTP_PROXY and OPENSSL_CONF and keeps SNYK_*', () => {
    const env = { HTTP_PROXY: 'internal', OPENSSL_CONF: 'internal', SNYK_TOKEN: 't' };
    const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp', SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' };
    assert.deepEqual(cleanSnykEnv(env, systemEnv, { restoreProxy: true, restoreOpenSSLConf: true, removeSnykVars: false }),
      { HTTP_PROXY: 'corp', OPENSSL_CONF: '/corp.cnf', SNYK_TOKEN: 't' });
  });
});

describe('inputs', () => {
  test('cleanSnykEnv returns new objects and mutates neither input', () => {
    const env = { PATH: '/usr/bin', SNYK_TOKEN: 't', Http_Proxy: 'a', HTTP_PROXY: 'b', OPENSSL_CONF: 'c' };
    const systemEnv = { SNYK_SYSTEM_HTTP_PROXY: 'corp', SNYK_SYSTEM_OPENSSL_CONF: '/corp.cnf' };
    const envBefore = { ...env };
    const systemEnvBefore = { ...systemEnv };
    const options = { restoreProxy: true, restoreOpenSSLConf: true, lowercaseProxy: true };

    const result = cleanSnykEnv(env, systemEnv, { ...options, removeSnykVars: false });
    const cleaned = cleanSnykEnv(env, systemEnv, options);

    assert.notEqual(result, env);
    assert.notEqual(cleaned, env);
    assert.deepEqual(env, envBefore);
    assert.deepEqual(systemEnv, systemEnvBefore);
  });

  test('does not read process.env', () => {
    const key = 'SNYK_SYSTEM_HTTP_PROXY';
    const original = process.env[key];
    process.env[key] = 'from-process-env';

    try {
      const env = { PATH: '/usr/bin' };
      const options = { restoreProxy: true, restoreOpenSSLConf: true, lowercaseProxy: true };

      assert.deepEqual(cleanSnykEnv(env, {}, options), { PATH: '/usr/bin' });
      assert.deepEqual(cleanSnykEnv(env, {}, { ...options, removeSnykVars: false }), { PATH: '/usr/bin' });
    } finally {
      if (original === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = original;
      }
    }
  });
});

describe('package exports', () => {
  test('exports cleanSnykEnv and not restoreSystemEnv', () => {
    assert.equal(indexExports.cleanSnykEnv, cleanSnykEnv);
    assert.equal('restoreSystemEnv' in indexExports, false);
  });

  test('keeps legacy exports', () => {
    assert.equal(typeof indexExports.legacyPlugin, 'object');
    assert.equal(typeof indexExports.legacyMonitor, 'object');
    assert.equal(typeof indexExports.legacyCommon, 'object');
  });
});

// Runs a real child process: it must see the restored uppercase proxy and no SNYK_* variables.
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
  env.SNYK_SYSTEM_HTTP_PROXY = 'http://user-proxy:3128';
  env.SNYK_SYSTEM_HTTPS_PROXY = 'http://user-proxy:3128';
  env.SNYK_SYSTEM_NO_PROXY = 'localhost';
  env.SNYK_TOKEN = 'tok-secret-value';
  env.snyk_oauth_token = 'oauth-secret-value';

  const childEnv = cleanSnykEnv(env, env, { restoreProxy: true });
  const script = 'process.stdout.write(JSON.stringify(process.env))';
  const result = spawnSync(process.execPath, ['-e', script], { env: childEnv, encoding: 'utf8', timeout: 30000 });

  assert.equal(result.status, 0, result.stderr || String(result.error));

  const childVars = JSON.parse(result.stdout);
  assert.equal(childVars.HTTP_PROXY, 'http://user-proxy:3128');
  for (const key of Object.keys(childVars)) {
    assert.doesNotMatch(key, /^SNYK_/i);
  }
  assert.doesNotMatch(result.stdout, /secret-proxy-pw|tok-secret-value|oauth-secret-value/);
});
