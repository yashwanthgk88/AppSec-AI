/**
 * Control Flow Graph (CFG) Builder
 *
 * Builds a Control Flow Graph from the parsed IR, enabling path-sensitive
 * analysis and reachability computation.
 */

import {
    ControlFlowGraph,
    CFGNode,
    CFGEdge,
    CFGNodeType,
    CFGEdgeType,
    IRNode,
    FunctionNode,
    MethodNode,
    BlockNode,
    IfNode,
    ForNode,
    ForEachNode,
    WhileNode,
    TryNode,
    SwitchNode,
    ReturnNode,
    ThrowNode
} from '../types';

export class CFGBuilder {
    private nodeId: number = 0;
    private nodes: Map<string, CFGNode> = new Map();
    private edges: CFGEdge[] = [];
    private currentBreakTarget: CFGNode | null = null;
    private currentContinueTarget: CFGNode | null = null;

    /**
     * Build a CFG for a function or method
     */
    build(func: FunctionNode | MethodNode): ControlFlowGraph {
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
        } else {
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

    private reset(): void {
        this.nodeId = 0;
        this.nodes = new Map();
        this.edges = [];
        this.currentBreakTarget = null;
        this.currentContinueTarget = null;
    }

    private createNode(type: CFGNodeType, astNode?: IRNode): CFGNode {
        const id = `cfg_${++this.nodeId}`;
        const node: CFGNode = {
            id,
            type,
            astNode,
            predecessors: [],
            successors: []
        };
        this.nodes.set(id, node);
        return node;
    }

    private addEdge(from: CFGNode, to: CFGNode, type: CFGEdgeType, condition?: IRNode): void {
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

    private buildBlock(block: BlockNode, predecessor: CFGNode): CFGNode | null {
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

    private buildStatement(stmt: IRNode, predecessor: CFGNode): CFGNode | null {
        switch (stmt.type) {
            case 'If':
                return this.buildIf(stmt as IfNode, predecessor);
            case 'For':
                return this.buildFor(stmt as ForNode, predecessor);
            case 'ForEach':
                return this.buildForEach(stmt as ForEachNode, predecessor);
            case 'While':
                return this.buildWhile(stmt as WhileNode, predecessor);
            case 'DoWhile':
                return this.buildDoWhile(stmt as any, predecessor);
            case 'Switch':
                return this.buildSwitch(stmt as SwitchNode, predecessor);
            case 'Try':
                return this.buildTry(stmt as TryNode, predecessor);
            case 'Return':
                return this.buildReturn(stmt as ReturnNode, predecessor);
            case 'Throw':
                return this.buildThrow(stmt as ThrowNode, predecessor);
            case 'Break':
                return this.buildBreak(predecessor);
            case 'Continue':
                return this.buildContinue(predecessor);
            case 'Block':
                return this.buildBlock(stmt as BlockNode, predecessor);
            default:
                return this.buildBasicStatement(stmt, predecessor);
        }
    }

    private buildBasicStatement(stmt: IRNode, predecessor: CFGNode): CFGNode {
        const node = this.createNode('basic', stmt);
        this.addEdge(predecessor, node, 'unconditional');
        return node;
    }

    private buildIf(stmt: IfNode, predecessor: CFGNode): CFGNode {
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
            let elseExit: CFGNode | null;
            if (stmt.elseBranch.type === 'If') {
                elseExit = this.buildIf(stmt.elseBranch as IfNode, branch);
            } else {
                elseExit = this.buildBlock(stmt.elseBranch as BlockNode, branch);
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
        } else {
            // No else - direct edge to merge
            this.addEdge(branch, merge, 'false-branch');
        }

        return merge;
    }

    private buildFor(stmt: ForNode, predecessor: CFGNode): CFGNode {
        let current = predecessor;

        // Build initialization
        if (stmt.init) {
            current = this.buildStatement(stmt.init, current)!;
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
            } else {
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

    private buildForEach(stmt: ForEachNode, predecessor: CFGNode): CFGNode {
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

    private buildWhile(stmt: WhileNode, predecessor: CFGNode): CFGNode {
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

    private buildDoWhile(stmt: any, predecessor: CFGNode): CFGNode {
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

    private buildSwitch(stmt: SwitchNode, predecessor: CFGNode): CFGNode {
        const switchNode = this.createNode('branch', stmt.discriminant);
        this.addEdge(predecessor, switchNode, 'unconditional');

        const switchExit = this.createNode('merge');

        const prevBreak = this.currentBreakTarget;
        this.currentBreakTarget = switchExit;

        let previousCaseExit: CFGNode | null = null;
        let hasDefault = false;

        for (const caseClause of stmt.cases) {
            const caseStart = this.createNode('basic', caseClause);

            // Edge from switch to this case
            if (caseClause.test === null) {
                // Default case
                hasDefault = true;
                this.addEdge(switchNode, caseStart, 'unconditional');
            } else {
                this.addEdge(switchNode, caseStart, 'true-branch', caseClause.test);
            }

            // Fallthrough from previous case
            if (previousCaseExit) {
                this.addEdge(previousCaseExit, caseStart, 'fallthrough');
            }

            // Build case body
            let current: CFGNode | null = caseStart;
            for (const stmt of caseClause.consequent) {
                if (!current) break;
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

    private buildTry(stmt: TryNode, predecessor: CFGNode): CFGNode {
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
        } else if (tryBodyExit) {
            this.addEdge(tryBodyExit, tryExit, 'unconditional');
        }

        return tryExit;
    }

    private buildReturn(stmt: ReturnNode, predecessor: CFGNode): null {
        const returnNode = this.createNode('return', stmt);
        this.addEdge(predecessor, returnNode, 'unconditional');
        // Return is terminal - no successor in this path
        return null;
    }

    private buildThrow(stmt: ThrowNode, predecessor: CFGNode): null {
        const throwNode = this.createNode('throw', stmt);
        this.addEdge(predecessor, throwNode, 'unconditional');
        // Throw is terminal - no successor in this path
        return null;
    }

    private buildBreak(predecessor: CFGNode): null {
        if (this.currentBreakTarget) {
            this.addEdge(predecessor, this.currentBreakTarget, 'unconditional');
        }
        return null;
    }

    private buildContinue(predecessor: CFGNode): null {
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
    private computeDominators(entry: CFGNode): void {
        const allNodes = new Set(this.nodes.keys());

        // Initialize: entry dominates only itself, others dominated by all
        for (const [id, node] of this.nodes) {
            if (node === entry) {
                node.dominators = new Set([id]);
            } else {
                node.dominators = new Set(allNodes);
            }
        }

        // Iterate until fixpoint
        let changed = true;
        while (changed) {
            changed = false;

            for (const [id, node] of this.nodes) {
                if (node === entry) continue;

                // Dom(n) = {n} ∪ ∩{Dom(p) | p ∈ preds(n)}
                let newDom: Set<string>;

                if (node.predecessors.length === 0) {
                    newDom = new Set([id]);
                } else {
                    // Start with intersection of all predecessors' dominators
                    newDom = new Set(node.predecessors[0].dominators!);
                    for (let i = 1; i < node.predecessors.length; i++) {
                        const predDom = node.predecessors[i].dominators!;
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
                if (newDom.size !== node.dominators!.size ||
                    ![...newDom].every(d => node.dominators!.has(d))) {
                    node.dominators = newDom;
                    changed = true;
                }
            }
        }
    }

    /**
     * Compute post-dominators (useful for finding nodes that must be reached)
     */
    computePostDominators(exit: CFGNode): void {
        const allNodes = new Set(this.nodes.keys());

        // Initialize: exit post-dominates only itself
        for (const [id, node] of this.nodes) {
            if (node === exit) {
                node.postDominators = new Set([id]);
            } else {
                node.postDominators = new Set(allNodes);
            }
        }

        // Iterate until fixpoint (same algorithm, but traversing successors)
        let changed = true;
        while (changed) {
            changed = false;

            for (const [id, node] of this.nodes) {
                if (node === exit) continue;

                let newPostDom: Set<string>;

                if (node.successors.length === 0) {
                    newPostDom = new Set([id]);
                } else {
                    newPostDom = new Set(node.successors[0].postDominators!);
                    for (let i = 1; i < node.successors.length; i++) {
                        const succPostDom = node.successors[i].postDominators!;
                        for (const d of newPostDom) {
                            if (!succPostDom.has(d)) {
                                newPostDom.delete(d);
                            }
                        }
                    }
                    newPostDom.add(id);
                }

                if (newPostDom.size !== node.postDominators!.size ||
                    ![...newPostDom].every(d => node.postDominators!.has(d))) {
                    node.postDominators = newPostDom;
                    changed = true;
                }
            }
        }
    }
}

// ============================================================================
// CFG Analysis Utilities
// ============================================================================

export class CFGAnalyzer {
    /**
     * Find all paths between two nodes (up to a maximum count)
     */
    static findPaths(
        from: CFGNode,
        to: CFGNode,
        maxPaths: number = 100
    ): CFGNode[][] {
        const paths: CFGNode[][] = [];
        const visited = new Set<string>();

        function dfs(current: CFGNode, path: CFGNode[]): void {
            if (paths.length >= maxPaths) return;

            if (current === to) {
                paths.push([...path, current]);
                return;
            }

            if (visited.has(current.id)) return;
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
    static isReachable(from: CFGNode, to: CFGNode): boolean {
        const visited = new Set<string>();
        const queue: CFGNode[] = [from];

        while (queue.length > 0) {
            const current = queue.shift()!;

            if (current === to) return true;
            if (visited.has(current.id)) continue;

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
    static topologicalSort(cfg: ControlFlowGraph): CFGNode[] {
        const result: CFGNode[] = [];
        const visited = new Set<string>();
        const stack = new Set<string>(); // For cycle detection

        function visit(node: CFGNode): void {
            if (stack.has(node.id)) {
                // Cycle detected - skip
                return;
            }
            if (visited.has(node.id)) return;

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
    static findLoops(cfg: ControlFlowGraph): Array<{ header: CFGNode; backEdge: CFGEdge }> {
        const loops: Array<{ header: CFGNode; backEdge: CFGEdge }> = [];

        for (const edge of cfg.edges) {
            const fromNode = cfg.nodes.get(edge.from)!;
            const toNode = cfg.nodes.get(edge.to)!;

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
    static getCyclomaticComplexity(cfg: ControlFlowGraph): number {
        const edges = cfg.edges.length;
        const nodes = cfg.nodes.size;
        return edges - nodes + 2;
    }
}
