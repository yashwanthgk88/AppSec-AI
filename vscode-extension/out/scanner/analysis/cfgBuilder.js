"use strict";
/**
 * Control Flow Graph (CFG) Builder
 *
 * Builds a Control Flow Graph from the parsed IR, enabling path-sensitive
 * analysis and reachability computation.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.CFGAnalyzer = exports.CFGBuilder = void 0;
class CFGBuilder {
    constructor() {
        this.nodeId = 0;
        this.nodes = new Map();
        this.edges = [];
        this.currentBreakTarget = null;
        this.currentContinueTarget = null;
    }
    /**
     * Build a CFG for a function or method
     */
    build(func) {
        this.reset();
        // Create entry and exit nodes
        const entry = this.createNode('entry');
        const exit = this.createNode('exit');
        if (func.body) {
            // Build CFG for function body
            const bodyExit = this.buildBlock(func.body, entry);
            if (bodyExit) {
                this.addEdge(bodyExit, exit, 'unconditional');
            }
        }
        else {
            this.addEdge(entry, exit, 'unconditional');
        }
        // Compute dominators (optional but useful for advanced analysis)
        this.computeDominators(entry);
        return {
            entry,
            exit,
            nodes: this.nodes,
            edges: this.edges
        };
    }
    reset() {
        this.nodeId = 0;
        this.nodes = new Map();
        this.edges = [];
        this.currentBreakTarget = null;
        this.currentContinueTarget = null;
    }
    createNode(type, astNode) {
        const id = `cfg_${++this.nodeId}`;
        const node = {
            id,
            type,
            astNode,
            predecessors: [],
            successors: []
        };
        this.nodes.set(id, node);
        return node;
    }
    addEdge(from, to, type, condition) {
        from.successors.push(to);
        to.predecessors.push(from);
        this.edges.push({
            from: from.id,
            to: to.id,
            type,
            condition
        });
    }
    // ========================================================================
    // Statement Processing
    // ========================================================================
    buildBlock(block, predecessor) {
        let current = predecessor;
        for (const stmt of block.statements) {
            const result = this.buildStatement(stmt, current);
            if (!result) {
                // Statement is a terminal (return, throw, etc.)
                return null;
            }
            current = result;
        }
        return current;
    }
    buildStatement(stmt, predecessor) {
        switch (stmt.type) {
            case 'If':
                return this.buildIf(stmt, predecessor);
            case 'For':
                return this.buildFor(stmt, predecessor);
            case 'ForEach':
                return this.buildForEach(stmt, predecessor);
            case 'While':
                return this.buildWhile(stmt, predecessor);
            case 'DoWhile':
                return this.buildDoWhile(stmt, predecessor);
            case 'Switch':
                return this.buildSwitch(stmt, predecessor);
            case 'Try':
                return this.buildTry(stmt, predecessor);
            case 'Return':
                return this.buildReturn(stmt, predecessor);
            case 'Throw':
                return this.buildThrow(stmt, predecessor);
            case 'Break':
                return this.buildBreak(predecessor);
            case 'Continue':
                return this.buildContinue(predecessor);
            case 'Block':
                return this.buildBlock(stmt, predecessor);
            default:
                return this.buildBasicStatement(stmt, predecessor);
        }
    }
    buildBasicStatement(stmt, predecessor) {
        const node = this.createNode('basic', stmt);
        this.addEdge(predecessor, node, 'unconditional');
        return node;
    }
    buildIf(stmt, predecessor) {
        // Create branch node for condition
        const branch = this.createNode('branch', stmt.condition);
        this.addEdge(predecessor, branch, 'unconditional');
        // Create merge node
        const merge = this.createNode('merge');
        // Build then branch
        const thenExit = this.buildBlock(stmt.thenBranch, branch);
        if (thenExit) {
            this.addEdge(thenExit, merge, 'unconditional');
        }
        // Mark true edge
        if (branch.successors.length > 0) {
            const lastEdgeIndex = this.edges.length - (thenExit ? 1 : 0) - 1;
            if (lastEdgeIndex >= 0 && this.edges[lastEdgeIndex]) {
                // Find the edge from branch to then block
                for (let i = this.edges.length - 1; i >= 0; i--) {
                    if (this.edges[i].from === branch.id && this.edges[i].type === 'unconditional') {
                        this.edges[i].type = 'true-branch';
                        this.edges[i].condition = stmt.condition;
                        break;
                    }
                }
            }
        }
        // Build else branch
        if (stmt.elseBranch) {
            let elseExit;
            if (stmt.elseBranch.type === 'If') {
                elseExit = this.buildIf(stmt.elseBranch, branch);
            }
            else {
                elseExit = this.buildBlock(stmt.elseBranch, branch);
            }
            if (elseExit) {
                this.addEdge(elseExit, merge, 'unconditional');
            }
            // Mark false edge
            for (let i = this.edges.length - 1; i >= 0; i--) {
                if (this.edges[i].from === branch.id && this.edges[i].type === 'unconditional') {
                    this.edges[i].type = 'false-branch';
                    break;
                }
            }
        }
        else {
            // No else - direct edge to merge
            this.addEdge(branch, merge, 'false-branch');
        }
        return merge;
    }
    buildFor(stmt, predecessor) {
        let current = predecessor;
        // Build initialization
        if (stmt.init) {
            current = this.buildStatement(stmt.init, current);
        }
        // Create loop header (condition check)
        const loopHeader = this.createNode('loop-header', stmt.test);
        this.addEdge(current, loopHeader, 'unconditional');
        // Create loop exit
        const loopExit = this.createNode('loop-exit');
        // Save break/continue targets
        const prevBreak = this.currentBreakTarget;
        const prevContinue = this.currentContinueTarget;
        this.currentBreakTarget = loopExit;
        // Create update node for continue target
        const updateNode = stmt.update
            ? this.createNode('basic', stmt.update)
            : loopHeader;
        this.currentContinueTarget = updateNode;
        // Build loop body
        const bodyExit = this.buildBlock(stmt.body, loopHeader);
        // Add true edge from header to body
        for (let i = this.edges.length - 1; i >= 0; i--) {
            if (this.edges[i].from === loopHeader.id && this.edges[i].type === 'unconditional') {
                this.edges[i].type = 'true-branch';
                this.edges[i].condition = stmt.test;
                break;
            }
        }
        // Body flows to update (or back to header if no update)
        if (bodyExit) {
            if (stmt.update && updateNode !== loopHeader) {
                this.addEdge(bodyExit, updateNode, 'unconditional');
                this.addEdge(updateNode, loopHeader, 'unconditional');
            }
            else {
                this.addEdge(bodyExit, loopHeader, 'unconditional');
            }
        }
        // False edge exits loop
        this.addEdge(loopHeader, loopExit, 'false-branch');
        // Restore break/continue targets
        this.currentBreakTarget = prevBreak;
        this.currentContinueTarget = prevContinue;
        return loopExit;
    }
    buildForEach(stmt, predecessor) {
        // Similar structure to for loop
        const loopHeader = this.createNode('loop-header', stmt.iterable);
        this.addEdge(predecessor, loopHeader, 'unconditional');
        const loopExit = this.createNode('loop-exit');
        const prevBreak = this.currentBreakTarget;
        const prevContinue = this.currentContinueTarget;
        this.currentBreakTarget = loopExit;
        this.currentContinueTarget = loopHeader;
        const bodyExit = this.buildBlock(stmt.body, loopHeader);
        // Mark the edge to body as true-branch
        for (let i = this.edges.length - 1; i >= 0; i--) {
            if (this.edges[i].from === loopHeader.id && this.edges[i].type === 'unconditional') {
                this.edges[i].type = 'true-branch';
                break;
            }
        }
        if (bodyExit) {
            this.addEdge(bodyExit, loopHeader, 'unconditional');
        }
        this.addEdge(loopHeader, loopExit, 'false-branch');
        this.currentBreakTarget = prevBreak;
        this.currentContinueTarget = prevContinue;
        return loopExit;
    }
    buildWhile(stmt, predecessor) {
        const loopHeader = this.createNode('loop-header', stmt.test);
        this.addEdge(predecessor, loopHeader, 'unconditional');
        const loopExit = this.createNode('loop-exit');
        const prevBreak = this.currentBreakTarget;
        const prevContinue = this.currentContinueTarget;
        this.currentBreakTarget = loopExit;
        this.currentContinueTarget = loopHeader;
        const bodyExit = this.buildBlock(stmt.body, loopHeader);
        // Mark the edge to body as true-branch
        for (let i = this.edges.length - 1; i >= 0; i--) {
            if (this.edges[i].from === loopHeader.id && this.edges[i].type === 'unconditional') {
                this.edges[i].type = 'true-branch';
                this.edges[i].condition = stmt.test;
                break;
            }
        }
        if (bodyExit) {
            this.addEdge(bodyExit, loopHeader, 'unconditional');
        }
        this.addEdge(loopHeader, loopExit, 'false-branch');
        this.currentBreakTarget = prevBreak;
        this.currentContinueTarget = prevContinue;
        return loopExit;
    }
    buildDoWhile(stmt, predecessor) {
        // Body is executed at least once
        const bodyStart = this.createNode('basic');
        this.addEdge(predecessor, bodyStart, 'unconditional');
        const loopHeader = this.createNode('loop-header', stmt.test);
        const loopExit = this.createNode('loop-exit');
        const prevBreak = this.currentBreakTarget;
        const prevContinue = this.currentContinueTarget;
        this.currentBreakTarget = loopExit;
        this.currentContinueTarget = loopHeader;
        const bodyExit = this.buildBlock(stmt.body, bodyStart);
        if (bodyExit) {
            this.addEdge(bodyExit, loopHeader, 'unconditional');
        }
        // True branch goes back to body
        this.addEdge(loopHeader, bodyStart, 'true-branch', stmt.test);
        // False branch exits
        this.addEdge(loopHeader, loopExit, 'false-branch');
        this.currentBreakTarget = prevBreak;
        this.currentContinueTarget = prevContinue;
        return loopExit;
    }
    buildSwitch(stmt, predecessor) {
        const switchNode = this.createNode('branch', stmt.discriminant);
        this.addEdge(predecessor, switchNode, 'unconditional');
        const switchExit = this.createNode('merge');
        const prevBreak = this.currentBreakTarget;
        this.currentBreakTarget = switchExit;
        let previousCaseExit = null;
        let hasDefault = false;
        for (const caseClause of stmt.cases) {
            const caseStart = this.createNode('basic', caseClause);
            // Edge from switch to this case
            if (caseClause.test === null) {
                // Default case
                hasDefault = true;
                this.addEdge(switchNode, caseStart, 'unconditional');
            }
            else {
                this.addEdge(switchNode, caseStart, 'true-branch', caseClause.test);
            }
            // Fallthrough from previous case
            if (previousCaseExit) {
                this.addEdge(previousCaseExit, caseStart, 'fallthrough');
            }
            // Build case body
            let current = caseStart;
            for (const stmt of caseClause.consequent) {
                if (!current)
                    break;
                current = this.buildStatement(stmt, current);
            }
            previousCaseExit = current;
        }
        // If last case doesn't break, flows to exit
        if (previousCaseExit) {
            this.addEdge(previousCaseExit, switchExit, 'unconditional');
        }
        // If no default case, switch can fall through directly
        if (!hasDefault) {
            this.addEdge(switchNode, switchExit, 'false-branch');
        }
        this.currentBreakTarget = prevBreak;
        return switchExit;
    }
    buildTry(stmt, predecessor) {
        const tryStart = this.createNode('try');
        this.addEdge(predecessor, tryStart, 'unconditional');
        const tryExit = this.createNode('merge');
        // Build try body
        const tryBodyExit = this.buildBlock(stmt.body, tryStart);
        // Build catch handlers
        for (const handler of stmt.handlers) {
            const catchNode = this.createNode('catch', handler);
            // Exception edge from try to catch
            this.addEdge(tryStart, catchNode, 'exception');
            // Build catch body
            const catchBodyExit = this.buildBlock(handler.body, catchNode);
            if (catchBodyExit) {
                this.addEdge(catchBodyExit, tryExit, 'unconditional');
            }
        }
        // Try body success flows to exit or finally
        if (stmt.finalizer) {
            const finallyNode = this.createNode('finally');
            if (tryBodyExit) {
                this.addEdge(tryBodyExit, finallyNode, 'unconditional');
            }
            // Build finally body
            const finallyExit = this.buildBlock(stmt.finalizer, finallyNode);
            if (finallyExit) {
                this.addEdge(finallyExit, tryExit, 'unconditional');
            }
        }
        else if (tryBodyExit) {
            this.addEdge(tryBodyExit, tryExit, 'unconditional');
        }
        return tryExit;
    }
    buildReturn(stmt, predecessor) {
        const returnNode = this.createNode('return', stmt);
        this.addEdge(predecessor, returnNode, 'unconditional');
        // Return is terminal - no successor in this path
        return null;
    }
    buildThrow(stmt, predecessor) {
        const throwNode = this.createNode('throw', stmt);
        this.addEdge(predecessor, throwNode, 'unconditional');
        // Throw is terminal - no successor in this path
        return null;
    }
    buildBreak(predecessor) {
        if (this.currentBreakTarget) {
            this.addEdge(predecessor, this.currentBreakTarget, 'unconditional');
        }
        return null;
    }
    buildContinue(predecessor) {
        if (this.currentContinueTarget) {
            this.addEdge(predecessor, this.currentContinueTarget, 'unconditional');
        }
        return null;
    }
    // ========================================================================
    // Dominator Computation
    // ========================================================================
    /**
     * Compute dominators using the iterative algorithm
     * A node D dominates node N if every path from entry to N passes through D
     */
    computeDominators(entry) {
        const allNodes = new Set(this.nodes.keys());
        // Initialize: entry dominates only itself, others dominated by all
        for (const [id, node] of this.nodes) {
            if (node === entry) {
                node.dominators = new Set([id]);
            }
            else {
                node.dominators = new Set(allNodes);
            }
        }
        // Iterate until fixpoint
        let changed = true;
        while (changed) {
            changed = false;
            for (const [id, node] of this.nodes) {
                if (node === entry)
                    continue;
                // Dom(n) = {n} ∪ ∩{Dom(p) | p ∈ preds(n)}
                let newDom;
                if (node.predecessors.length === 0) {
                    newDom = new Set([id]);
                }
                else {
                    // Start with intersection of all predecessors' dominators
                    newDom = new Set(node.predecessors[0].dominators);
                    for (let i = 1; i < node.predecessors.length; i++) {
                        const predDom = node.predecessors[i].dominators;
                        for (const d of newDom) {
                            if (!predDom.has(d)) {
                                newDom.delete(d);
                            }
                        }
                    }
                    // Add self
                    newDom.add(id);
                }
                // Check if changed
                if (newDom.size !== node.dominators.size ||
                    ![...newDom].every(d => node.dominators.has(d))) {
                    node.dominators = newDom;
                    changed = true;
                }
            }
        }
    }
    /**
     * Compute post-dominators (useful for finding nodes that must be reached)
     */
    computePostDominators(exit) {
        const allNodes = new Set(this.nodes.keys());
        // Initialize: exit post-dominates only itself
        for (const [id, node] of this.nodes) {
            if (node === exit) {
                node.postDominators = new Set([id]);
            }
            else {
                node.postDominators = new Set(allNodes);
            }
        }
        // Iterate until fixpoint (same algorithm, but traversing successors)
        let changed = true;
        while (changed) {
            changed = false;
            for (const [id, node] of this.nodes) {
                if (node === exit)
                    continue;
                let newPostDom;
                if (node.successors.length === 0) {
                    newPostDom = new Set([id]);
                }
                else {
                    newPostDom = new Set(node.successors[0].postDominators);
                    for (let i = 1; i < node.successors.length; i++) {
                        const succPostDom = node.successors[i].postDominators;
                        for (const d of newPostDom) {
                            if (!succPostDom.has(d)) {
                                newPostDom.delete(d);
                            }
                        }
                    }
                    newPostDom.add(id);
                }
                if (newPostDom.size !== node.postDominators.size ||
                    ![...newPostDom].every(d => node.postDominators.has(d))) {
                    node.postDominators = newPostDom;
                    changed = true;
                }
            }
        }
    }
}
exports.CFGBuilder = CFGBuilder;
// ============================================================================
// CFG Analysis Utilities
// ============================================================================
class CFGAnalyzer {
    /**
     * Find all paths between two nodes (up to a maximum count)
     */
    static findPaths(from, to, maxPaths = 100) {
        const paths = [];
        const visited = new Set();
        function dfs(current, path) {
            if (paths.length >= maxPaths)
                return;
            if (current === to) {
                paths.push([...path, current]);
                return;
            }
            if (visited.has(current.id))
                return;
            visited.add(current.id);
            path.push(current);
            for (const succ of current.successors) {
                dfs(succ, path);
            }
            path.pop();
            visited.delete(current.id);
        }
        dfs(from, []);
        return paths;
    }
    /**
     * Check if a node is reachable from another node
     */
    static isReachable(from, to) {
        const visited = new Set();
        const queue = [from];
        while (queue.length > 0) {
            const current = queue.shift();
            if (current === to)
                return true;
            if (visited.has(current.id))
                continue;
            visited.add(current.id);
            for (const succ of current.successors) {
                if (!visited.has(succ.id)) {
                    queue.push(succ);
                }
            }
        }
        return false;
    }
    /**
     * Get all nodes in a CFG in topological order
     */
    static topologicalSort(cfg) {
        const result = [];
        const visited = new Set();
        const stack = new Set(); // For cycle detection
        function visit(node) {
            if (stack.has(node.id)) {
                // Cycle detected - skip
                return;
            }
            if (visited.has(node.id))
                return;
            stack.add(node.id);
            for (const succ of node.successors) {
                visit(succ);
            }
            stack.delete(node.id);
            visited.add(node.id);
            result.unshift(node);
        }
        visit(cfg.entry);
        // Add any unreached nodes
        for (const node of cfg.nodes.values()) {
            if (!visited.has(node.id)) {
                visit(node);
            }
        }
        return result;
    }
    /**
     * Find all loops in the CFG (back edges)
     */
    static findLoops(cfg) {
        const loops = [];
        for (const edge of cfg.edges) {
            const fromNode = cfg.nodes.get(edge.from);
            const toNode = cfg.nodes.get(edge.to);
            // A back edge goes from a node to one of its dominators
            if (fromNode.dominators?.has(toNode.id)) {
                loops.push({
                    header: toNode,
                    backEdge: edge
                });
            }
        }
        return loops;
    }
    /**
     * Get the cyclomatic complexity of the CFG
     * M = E - N + 2P (where P is the number of connected components, usually 1)
     */
    static getCyclomaticComplexity(cfg) {
        const edges = cfg.edges.length;
        const nodes = cfg.nodes.size;
        return edges - nodes + 2;
    }
}
exports.CFGAnalyzer = CFGAnalyzer;
//# sourceMappingURL=cfgBuilder.js.map