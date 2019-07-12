import { DepTree, ScannedProject, SupportedPackageManagers } from './common';

// Interface definitions for DepTree-returning dependency analysis plugins for Snyk CLI.

// Simple plugins.
export interface SingleSubprojectPlugin {
  inspect(root: string, targetFile?: string, options?: SingleSubprojectInspectOptions): Promise<SinglePackageResult>;

  // Recommended, for introspection / debugging.
  // Should ideally be required, but then all the implementations and test fakes will have to change.
  pluginName?(): string;

  flags?(): FlagSpecs;
}

// New-style plugins that can return multiple results (e.g. Gradle).
export interface Plugin extends SingleSubprojectPlugin {
  // Actual function should implement this
  inspect(root: string, targetFile?: string, options?: InspectOptions): Promise<InspectResult>;

  // But we also guarantee that for Single-/Multiple- options we produce Single-/Multiple- result.
  // The actual implementations should include these two lines to confirm the guarantee.
  inspect(root: string, targetFile?: string, options?: SingleSubprojectInspectOptions): Promise<SinglePackageResult>;
  inspect(root: string, targetFile?: string, options?: MultiSubprojectInspectOptions): Promise<MultiProjectResult>;
}

export function adaptSingleProjectPlugin(plugin: SingleSubprojectPlugin): Plugin {
  return { inspect: (root: string, targetFile?: string, options?: InspectOptions) => {
    if (options && isMultiSubProject(options)) {
      const name = plugin.pluginName ? plugin.pluginName() : '[unknown]';
      throw new Error(`Plugin ${name} does not support scanning multiple sub-projects`);
    } else {
      return plugin.inspect(root, targetFile, options);
    }
  }} as Plugin;
}

export interface BaseInspectOptions {
  // Include dev dependencies
  dev?: boolean;

  // Additional command line arguments to the underlying tool,
  // supplied after "--" to the Snyk CLI.
  // E.g. --configuration=foo
  args?: string[];
}

export interface SingleSubprojectInspectOptions extends BaseInspectOptions {
  // Return the information not on the main project,
  // but on the specific sub-project defined in the build.
  subProject?: string;
}

export interface MultiSubprojectInspectOptions extends BaseInspectOptions {

  // Return multiple "subprojects" as a MultiProjectResult.
  // Sub-projects correspond to sub-projects in Gradle or projects in a Yarn workspace.
  // Eventually, this flag will be an implicit default and all the plugins
  // will return MultiProjectResult.

  // NOTE: old versions of snyk-gradle-plugin have used `multiDepRoots`
  allSubProjects: true;
}

export type InspectOptions = SingleSubprojectInspectOptions | MultiSubprojectInspectOptions;

export type InspectResult = SinglePackageResult | MultiProjectResult;

export function isMultiSubProject(options: InspectOptions):
    options is MultiSubprojectInspectOptions {
  return (options as MultiSubprojectInspectOptions).allSubProjects;
}

export interface PluginMetadata {
  name: string;
  runtime?: string;

  // TODO(BST-542): remove, DepRoot.targetFile to be used instead
  // Note: can be missing, see targetFileFilteredForCompatibility
  targetFile?: string;

  packageManager?: SupportedPackageManagers;

  // Per-plugin custom metadata
  meta?: {
    allSubProjectNames?: string[];
  };

  // Docker-related fields
  dockerImageId?: any;
  imageLayers?: any;
}

export interface SinglePackageResult {
  plugin: PluginMetadata;
  package: DepTree;
}

export interface MultiProjectResult {
  plugin: PluginMetadata;

  // NOTE: old versions of snyk-gradle-plugin have used `depRoots`
  scannedProjects: ScannedProject[];
}

export function isMultiResult(res: InspectResult): res is MultiProjectResult {
  return !!(res as MultiProjectResult).scannedProjects;
}

// The specification for plugin-specific user-visible flags (e.g. those that should be supplied via the CLI).
// Note that a plugin can also have other, implicitly provided arguments.
export interface FlagSpecs {
  // Note: the flag name here is specified in `camelCase`, to conform to Javascript variable/field naming standards.
  // The flag specified in the command line will be in the `--dash-case`, and the CLI argument parses should convert
  // all the flag names to camelCase automatically.
  [nameCamelCase: string]: FlagSpec;
}

export interface FlagSpec {
  // Flag type.
  // Boolean flags can be specified as `--flag-name`
  // String and numeric flags as `--flag-name=value`
  // Note: as of the moment of writing, `--flag-name value` syntax is not supported.
  type: 'boolean' | 'string' | 'number';

  // Plain text documentation, to be presented via `snyk help`.
  // Some Markdown elements might be allowed, but they are not guaranteed to render nicely.
  docPlainText: string;

  // Default flag value. If not provided, or explicitly described in the documentation,
  // should be generally assumed falsy for booleans, and "unconstrained" for numeric-
  // and string-based constraints.
  default?: boolean | string | number;

  // Snyk CLI subcommands that the flag applies to.
  // By default, it's assumed that it's test, monitor and wizard.
  subCommands?: string[];

  // A validator function. Throws an error if the argument is invalid.
  validator?: (x: string) => void;
}
