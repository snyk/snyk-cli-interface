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

## Contributing

To ensure the long-term stability and quality of this project, we are moving to a closed-contribution model effective August 2025. This change allows our core team to focus on a centralized development roadmap and rigorous quality assurance, which is essential for a component with such extensive usage.

All of our development will remain public for transparency. We thank the community for its support and valuable contributions.

## Getting Support

GitHub issues have been disabled on this repository as part of our move to a closed-contribution model. The Snyk support team does not actively monitor GitHub issues on any Snyk development project.

For help with the Snyk CLI or Snyk in general, please use the [Snyk support page](https://support.snyk.io/), which is the fastest way to get assistance.