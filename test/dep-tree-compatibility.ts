import * as depGraph from '@snyk/dep-graph';
import { legacyCommon as common } from '../index';

/// Note: if the type signature of the `DepTree` in the `@snyk/dep-graph`
/// package is incompatible with the `DepTree` defined in this package,
/// this file fails to compile.
const depTree: depGraph.legacy.DepTree = {}
export const legacyCommonDepTreeTyped: common.DepTree = depTree;
