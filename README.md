# snyk-cli-interface
Interface definitions for interactions between Snyk CLI and associated components:

* plugins for analyzing various build systems
* monitor states sent to snyk.io website

This library should be only imported from Typescript.

The types can be imported in one of the following ways:

* whole sub-module import from the top level

    import { legacyPlugin as api } from '@snyk/cli-interface';
    // use api.InspectOptions

* "deep import" (discouraged but possible)

    import { InspectOptions } from '@snyk/cli-interface/legacy/plugin';

The `npm` package does not follow the usual Snyk convention and
exports the build files in the root directory, not in dist, to enable "deep imports".

We still have to publish the package using the compiled files, because many tools in Node.js
ecosystem assume that published libraries should be always in Javascript.

## Sanitizing environments for child processes

Plugins spawn build tools such as Gradle or Maven, which run project code. Two pure helpers
build the env for those spawns. Both return a new object, never mutate their inputs and never read `process.env`.

* `cleanSnykEnv(env, systemEnv?)`: for third-party child processes. Restores the user's own proxy and OpenSSL
  settings from `SNYK_SYSTEM_*` and removes every `SNYK_*` variable (case-insensitive).
* `restoreSystemEnv(env, systemEnv?)`: for Snyk's own child processes. Undoes the CLI's proxy and OpenSSL
  overrides and keeps `SNYK_*` variables.

Pass `process.env` as `systemEnv` when `env` is built from a caller-supplied object:

    import { spawn } from 'child_process';
    import { cleanSnykEnv } from '@snyk/cli-interface';

    spawn(cmd, args, { env: cleanSnykEnv({ ...process.env, ...extra }) });
    // For a caller-supplied env, read the user's SNYK_SYSTEM_* values from process.env:
    // cleanSnykEnv(callerEnv, process.env)

## Contributing

To ensure the long-term stability and quality of this project, we are moving to a closed-contribution model effective August 2025. This change allows our core team to focus on a centralized development roadmap and rigorous quality assurance, which is essential for a component with such extensive usage.

All of our development will remain public for transparency. We thank the community for its support and valuable contributions.

## Getting Support

GitHub issues have been disabled on this repository as part of our move to a closed-contribution model. The Snyk support team does not actively monitor GitHub issues on any Snyk development project.

For help with the Snyk CLI or Snyk in general, please use the [Snyk support page](https://support.snyk.io/), which is the fastest way to get assistance.