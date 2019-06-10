import { DepTree, ScannedProject } from './common';

export interface Inspect {
  async (root: string, targetFile: string, options?: SingleRootInspectOptions): Promise<SinglePackageResult>;
  async (root: string, targetFile: string, options?: MultiRootsInspectOptions): Promise<MultiProjectResult>;
  async (root: string, targetFile: string, options?: SingleRootInspectOptions | MultiRootsInspectOptions): Promise<SinglePackageResult | MultiProjectResult>;
}

export interface BaseInspectOptions {
  dev?: boolean;

  // Additional command line arguments to Gradle,
  // supplied after "--" to the Snyk CLI.
  // E.g. --configuration=foo
  args?: string[];
}

export interface SingleRootInspectOptions extends BaseInspectOptions {
  // Return the information not on the main project,
  // but on the specific sub-project defined in the build.
  subProject?: string;
}

export interface MultiRootsInspectOptions extends BaseInspectOptions {

  // Return multiple "subprojects" as a MultiProjectResult.
  // Sub-projects correspond to sub-projects in Gradle or projects in a Yarn workspace.
  // Eventually, this flag will be an implicit default.
  // For now, plugins return SingleDepRootResult by default.

  // NOTE: old versions of snyk-gradle-plugin have used `multiDepRoots`
  allSubProjects: true;
}

export interface PluginMetadata {
  name: string;
  runtime: string;

  // TODO(BST-542): remove, DepRoot.targetFile to be used instead
  // Note: can be missing, see targetFileFilteredForCompatibility
  targetFile?: string;

  // Per-plugin custom metadata
  meta: {
    allSubProjectNames?: string[];
  };
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
