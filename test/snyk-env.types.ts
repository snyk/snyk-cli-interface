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

cleanSnykEnv({}, {}, { restoreProxy: true });
cleanSnykEnv({}, {}, { restoreProxy: { lowercase: true } });

// @ts-expect-error lowercaseProxy is gone; lowercasing is a restoreProxy sub-option
cleanSnykEnv({}, {}, { lowercaseProxy: true });

cleanSnykEnv({}, {}, { restoreProxy: {} });
cleanSnykEnv({}, {}, { restoreProxy: { removeIfEmpty: true } });
cleanSnykEnv({}, {}, { restoreProxy: { lowercase: true, removeIfEmpty: true } });

// @ts-expect-error misspelt restoreProxy sub-option is rejected
cleanSnykEnv({}, {}, { restoreProxy: { lowercas: true } });
