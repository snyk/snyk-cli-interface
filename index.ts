/**
 * A common interface for the plugins for build systems analyzed by Snyk.
 */
export interface Plugin {
  inspect(root, targetFile, options?: SingleRootInspectOptions): Promise<SingleDepRootResult>;
}

export interface SingleRootInspectOptions {
  dev?: boolean;

  'gradle-sub-project'?: string;
  args?: string[];
}

export interface SingleDepRootResult {
  plugin: PluginMetadata;
  package: DepTree;
}

interface PluginMetadata {
  name: string;
  runtime: string;
  targetFile?: string;
}

interface DepDict {
  [name: string]: DepTree;
}

interface DepTree {
  name: string;
  version: string;
  dependencies?: DepDict;
  packageFormatVersion?: string;
}
