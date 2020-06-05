import * as graphlib from '@snyk/graphlib';
import { DepGraph } from '@snyk/dep-graph';

export { DepGraph };
export interface DepTreeDep {
  name?: string; // shouldn't, but might be missing
  version?: string; // shouldn't, but might be missing
  dependencies?: {
    [depName: string]: DepTreeDep,
  };
  labels?: {
    [key: string]: string;

    // Known keys:
    // pruned: identical subtree already presents in the parent node.
    //         See --prune-repeated-subdependencies flag.
  };
}

export interface DepTree extends DepTreeDep {
  type?: string;
  packageFormatVersion?: string;
  targetOS?: {
    name: string;
    version: string;
  };

  // TODO: clarify which of these extra files are actually needed
  targetFile?: string;
  policy?: string;
  docker?: any;
  files?: any;
}

export interface ScannedProject {
  depTree?: DepTree; // to be soon replaced with depGraph
  depGraph?: DepGraph;

  // this will eventually become a structure (list) of "build" files,
  // also known as "project roots".
  // Note: can be missing, see targetFileFilteredForCompatibility
  targetFile?: string;

  meta?: any; // TODO(BST-542): decide on the format
  callGraph?: CallGraph;
}

export type SupportedPackageManagers =
  'rubygems' | // Ruby
  'npm' | 'yarn' | // Node.js
  'maven' | 'sbt' | 'gradle' | // JVM
  'golangdep' | 'govendor' | 'gomodules' | // Go
  'pip' | // Python
  'nuget' | 'paket' | // .Net
  'composer' | // PHP
  'rpm' | 'apk' | 'deb' | 'dockerfile' // Docker (Linux)
  ;

export type CallGraph = graphlib.Graph;
