import { DepTree, ScannedProject, SupportedPackageManagers } from './common';

export interface Plugin {
  inspect(root: string, targetFile?: string, options?: SingleSubprojectInspectOptions): Promise<SinglePackageResult>;
  inspect(root: string, targetFile?: string, options?: MultiSubprojectInspectOptions): Promise<MultiProjectResult>;
  inspect(root: string, targetFile?: string, options?: InspectOptions): Promise<InspectResult>;
}

export interface BaseInspectOptions {
  dev?: boolean;

  // Additional command line arguments to Gradle,
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
  // Eventually, this flag will be an implicit default.
  // For now, plugins return SingleDepRootResult by default.

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
  runtime: string;

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

// Legacy result type. Will be deprecated soon.
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
