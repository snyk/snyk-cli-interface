// Compile-time check only. `npm run build` (tsc) fails if either call below stops being
// a compile error, which is what happens when systemEnv is made optional again.
// This module is never loaded at runtime; its compiled output is git-ignored.
import { cleanSnykEnv, restoreSystemEnv } from '../snyk-env';

export function systemEnvIsRequired(): void {
  // @ts-expect-error systemEnv is required
  cleanSnykEnv({});

  // @ts-expect-error systemEnv is required
  restoreSystemEnv({});
}
