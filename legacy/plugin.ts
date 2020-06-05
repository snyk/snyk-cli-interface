import { CallGraph, DepGraph, DepTree, ScannedProject, SupportedPackageManagers } from './common';

// Interface definitions for DepTree-returning dependency analysis plugins for Snyk CLI.

// Simple plugins.
export interface SingleSubprojectPlugin {
  inspect(root: string, targetFile?: string, options?: SingleSubprojectInspectOptions): Promise<SinglePackageResult>;

  // Recommended, for introspection / debugging.
  // Should ideally be required, but then all the implementations and test fakes will have to change.
  pluginName?(): string;
}

// New-style plugins that can return multiple results (e.g. Gradle).
export interface Plugin extends SingleSubprojectPlugin {
  // Actual function should implement this
  inspect(root: string, targetFile?: string, options?: InspectOptions): Promise<InspectResult>;

  // But we also guarantee that for Single-/Multiple- options we produce Single-/Multiple- result.
  // The actual implementations should include these two declaration lines to confirm the guarantee.
  inspect(
    root: string,
    targetFile?: string,
    options?: SingleSubprojectInspectOptions,
    ): Promise<SinglePackageResult>;
  inspect(
    root: string,
    targetFile: string | undefined,
    options: MultiSubprojectInspectOptions,
    ): Promise<MultiProjectResult>;
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
  // Skip any deps we could not resolve, and continue
  skipUnresolved?: boolean;

  // Additional command line arguments to the underlying tool,
  // supplied after "--" to the Snyk CLI.
  // E.g. --configuration=foo
  args?: string[];

  // when true plugin should return a dep-graph
  // TODO(boost): remove when all plugins support returning dep-graph
  useDepGraph?: boolean;
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
    allSubProjectNames?: string[],
    versionBuildInfo?: VersionBuildInfo,
  };

  // Docker-related fields
  dockerImageId?: any;
  imageLayers?: any;
  packageFormatVersion?: string;
}

export interface VersionBuildInfo {
  gradleVersion?: string;
  metaBuildVersion: { [index: string]: string };
}

export interface SinglePackageResult {
  plugin: PluginMetadata;
  package: DepTree;
  dependencyGraph?: DepGraph;
  callGraph?: CallGraph;
  meta?: {
    gradleProjectName?: string,
    versionBuildInfo?: VersionBuildInfo,
  };
}

export interface MultiProjectResult {
  plugin: PluginMetadata;

  // NOTE: old versions of snyk-gradle-plugin have used `depRoots`
  scannedProjects: ScannedProject[];
}

export function isMultiResult(res: InspectResult): res is MultiProjectResult {
  return !!(res as MultiProjectResult).scannedProjects;
}
