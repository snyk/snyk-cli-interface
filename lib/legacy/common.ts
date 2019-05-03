export interface DepTreeDep {
  name?: string; // shouldn't, but might be missing
  version?: string; // shouldn't, but might be missing
  dependencies?: {
    [depName: string]: DepTreeDep,
  };
}

export interface DepTree extends DepTreeDep {
  type?: string;
  packageFormatVersion?: string;
  targetOS?: {
    name: string;
    version: string;
  };
}

export interface ScannedProject {
  depTree: DepTree; // to be soon replaced with depGraph

  // this will eventually become a structure (list) of "build" files,
  // also known as "project roots".
  // Note: can be missing, see targetFileFilteredForCompatibility
  targetFile?: string;

  meta?: any; // TODO(BST-542): decide on the format
}
