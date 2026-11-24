// Compile-time check only. `npm run build` (tsc) fails if any call below stops being
// a compile error, which is what happens when systemEnv is made optional again or
// unknown option keys are accepted.
// This module is never loaded at runtime; its compiled output is git-ignored.
import { cleanSnykEnv } from '../snyk-env';

export function systemEnvIsRequired(): void {
  // @ts-expect-error systemEnv is required
  cleanSnykEnv({});
}

// @ts-expect-error unknown option keys are rejected (restoreProxy is spelled restoreproxy)
cleanSnykEnv({}, {}, { restoreproxy: true });
