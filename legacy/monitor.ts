import { DepTree, DepGraph, ScannedArtifact } from './common';

export interface MonitorBody {
  meta: MonitorMeta;
  policy: string;
  /** @deprecated - Use "artifacts" instead. */
  package?: DepTree;
  /** @deprecated - Use "artifacts" instead. */
  dependencyGraph?: DepGraph;
  artifacts?: ScannedArtifact[];
  targetFile: string;
}

export interface MonitorMeta {
  method?: string;
  hostname: string;
  id: string;
  ci: boolean;
  pid: number;
  node: string;
  master: boolean;
  name: string;
  version: string;
  org?: string;
  pluginName: string;
  pluginRuntime: string;
  dockerImageId?: string;
  dockerBaseImage?: string;
  projectName: string;
}
