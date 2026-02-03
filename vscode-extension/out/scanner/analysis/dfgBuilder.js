"use strict";
/**
 * Data Flow Graph (DFG) Builder
 *
 * Builds data flow information including:
 * - Reaching Definitions: which definitions may reach a given point
 * - Def-Use Chains: linking definitions to their uses
 * - Use-Def Chains: linking uses to their definitions
 * - Live Variables: which variables are live at each point
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DFGAnalyzer = exports.DFGBuilder = void 0;
class DFGBuilder {
    constructor() {
        this.nodeId = 0;
        this.definitions = new Map(); // variable -> definitions
        this.uses = new Map(); // variable -> uses
        this.cfgToDefsMap = new Map(); // cfg node -> definitions
        this.cfgToUsesMap = new Map(); // cfg node -> uses
    }
    /**
     * Build a Data Flow Graph from a Control Flow Graph
     */
    build(cfg, symbolTable) {
        this.reset();
        // Phase 1: Collect all definitions and uses from CFG nodes
        this.collectDefsAndUses(cfg);
        // Phase 2: Compute reaching definitions
        const reachingDefs = this.computeReachingDefinitions(cfg);
        // Phase 3: Build def-use and use-def chains
        const { defUseChains, useDefChains } = this.buildChains(cfg, reachingDefs);
        // Phase 4: Build DFG nodes
        const nodes = this.buildDFGNodes(reachingDefs);
        return {
            nodes,
            defUseChains,
            useDefChains
        };
    }
    reset() {
        this.nodeId = 0;
        this.definitions = new Map();
        this.uses = new Map();
        this.cfgToDefsMap = new Map();
        this.cfgToUsesMap = new Map();
    }
    // ========================================================================
    // Phase 1: Collect Definitions and Uses
    // ========================================================================
    collectDefsAndUses(cfg) {
        for (const [id, cfgNode] of cfg.nodes) {
            if (!cfgNode.astNode)
                continue;
            const defs = this.extractDefinitions(cfgNode.astNode, cfgNode);
            const uses = this.extractUses(cfgNode.astNode, cfgNode);
            if (defs.length > 0) {
                this.cfgToDefsMap.set(id, defs);
                for (const def of defs) {
                    if (!this.definitions.has(def.variable)) {
                        this.definitions.set(def.variable, []);
                    }
                    this.definitions.get(def.variable).push(def);
                }
            }
            if (uses.length > 0) {
                this.cfgToUsesMap.set(id, uses);
                for (const use of uses) {
                    if (!this.uses.has(use.variable)) {
                        this.uses.set(use.variable, []);
                    }
                    this.uses.get(use.variable).push(use);
                }
            }
        }
    }
    extractDefinitions(node, cfgNode) {
        const defs = [];
        switch (node.type) {
            case 'VariableDeclaration':
                const varDecl = node;
                defs.push({
                    id: `def_${++this.nodeId}`,
                    variable: varDecl.name,
                    location: varDecl.location,
                    cfgNode
                });
                // Also extract uses from initializer
                break;
            case 'Assignment':
                const assign = node;
                const assignedVar = this.extractVariableName(assign.left);
                if (assignedVar) {
                    defs.push({
                        id: `def_${++this.nodeId}`,
                        variable: assignedVar,
                        location: assign.location,
                        cfgNode
                    });
                }
                break;
            case 'Parameter':
                const param = node;
                defs.push({
                    id: `def_${++this.nodeId}`,
                    variable: param.name,
                    location: param.location,
                    cfgNode
                });
                break;
        }
        // Recursively check children
        if (node.children) {
            for (const child of node.children) {
                defs.push(...this.extractDefinitions(child, cfgNode));
            }
        }
        return defs;
    }
    extractUses(node, cfgNode) {
        const uses = [];
        switch (node.type) {
            case 'Identifier':
                const ident = node;
                uses.push({
                    id: `use_${++this.nodeId}`,
                    variable: ident.name,
                    location: ident.location,
                    cfgNode
                });
                break;
            case 'MemberExpression':
                const member = node;
                // Add use of the base object
                uses.push(...this.extractUses(member.object, cfgNode));
                break;
            case 'CallExpression':
                const call = node;
                // Add uses from callee
                uses.push(...this.extractUses(call.callee, cfgNode));
                // Add uses from arguments
                for (const arg of call.arguments) {
                    uses.push(...this.extractUses(arg, cfgNode));
                }
                break;
            case 'BinaryExpression':
                const binary = node;
                uses.push(...this.extractUses(binary.left, cfgNode));
                uses.push(...this.extractUses(binary.right, cfgNode));
                break;
            case 'Assignment':
                const assign = node;
                // Only the right side is a use
                uses.push(...this.extractUses(assign.right, cfgNode));
                break;
            case 'VariableDeclaration':
                const varDecl = node;
                if (varDecl.initializer) {
                    uses.push(...this.extractUses(varDecl.initializer, cfgNode));
                }
                break;
            default:
                // Check children
                if (node.children) {
                    for (const child of node.children) {
                        uses.push(...this.extractUses(child, cfgNode));
                    }
                }
        }
        return uses;
    }
    extractVariableName(node) {
        if (node.type === 'Identifier') {
            return node.name;
        }
        if (node.type === 'MemberExpression') {
            // For member expressions, get the full path
            return this.getMemberExpressionPath(node);
        }
        return null;
    }
    getMemberExpressionPath(node) {
        const parts = [];
        let current = node;
        while (current.type === 'MemberExpression') {
            const member = current;
            if (member.property.type === 'Identifier') {
                parts.unshift(member.property.name);
            }
            current = member.object;
        }
        if (current.type === 'Identifier') {
            parts.unshift(current.name);
        }
        return parts.join('.');
    }
    // ========================================================================
    // Phase 2: Reaching Definitions Analysis
    // ========================================================================
    computeReachingDefinitions(cfg) {
        // For each CFG node, compute which definitions reach it
        const reachIn = new Map();
        const reachOut = new Map();
        // Initialize
        for (const id of cfg.nodes.keys()) {
            reachIn.set(id, new Set());
            reachOut.set(id, new Set());
        }
        // Compute gen and kill sets for each node
        const gen = new Map();
        const kill = new Map();
        for (const [id, cfgNode] of cfg.nodes) {
            const genSet = new Set();
            const killSet = new Set();
            const defs = this.cfgToDefsMap.get(id) || [];
            for (const def of defs) {
                genSet.add(def.id);
                // Kill all other definitions of the same variable
                const allDefs = this.definitions.get(def.variable) || [];
                for (const otherDef of allDefs) {
                    if (otherDef.id !== def.id) {
                        killSet.add(otherDef.id);
                    }
                }
            }
            gen.set(id, genSet);
            kill.set(id, killSet);
        }
        // Iterate until fixpoint
        let changed = true;
        while (changed) {
            changed = false;
            for (const [id, cfgNode] of cfg.nodes) {
                // ReachIn = ∪ ReachOut(predecessors)
                const newReachIn = new Set();
                for (const pred of cfgNode.predecessors) {
                    const predOut = reachOut.get(pred.id);
                    for (const def of predOut) {
                        newReachIn.add(def);
                    }
                }
                // ReachOut = Gen ∪ (ReachIn - Kill)
                const genSet = gen.get(id);
                const killSet = kill.get(id);
                const newReachOut = new Set(genSet);
                for (const def of newReachIn) {
                    if (!killSet.has(def)) {
                        newReachOut.add(def);
                    }
                }
                // Check if changed
                const oldOut = reachOut.get(id);
                if (newReachOut.size !== oldOut.size ||
                    ![...newReachOut].every(d => oldOut.has(d))) {
                    reachIn.set(id, newReachIn);
                    reachOut.set(id, newReachOut);
                    changed = true;
                }
            }
        }
        return reachIn;
    }
    // ========================================================================
    // Phase 3: Build Def-Use and Use-Def Chains
    // ========================================================================
    buildChains(cfg, reachingDefs) {
        const defUseChains = new Map();
        const useDefChains = new Map();
        // Create a map from definition ID to definition
        const defById = new Map();
        for (const defs of this.definitions.values()) {
            for (const def of defs) {
                defById.set(def.id, def);
            }
        }
        // For each use, find which definitions reach it
        for (const [cfgNodeId, uses] of this.cfgToUsesMap) {
            const reaching = reachingDefs.get(cfgNodeId) || new Set();
            for (const use of uses) {
                const reachingForVar = [];
                for (const defId of reaching) {
                    const def = defById.get(defId);
                    if (def && def.variable === use.variable) {
                        reachingForVar.push(def);
                    }
                }
                // Build use-def chain
                const useDfgNode = {
                    id: use.id,
                    variable: use.variable,
                    type: 'use',
                    location: use.location,
                    reachingDefinitions: new Set(reachingForVar.map(d => d.id)),
                    liveVariables: new Set()
                };
                useDefChains.set(use.id, {
                    use: useDfgNode,
                    definitions: reachingForVar.map(d => ({
                        id: d.id,
                        variable: d.variable,
                        type: 'definition',
                        location: d.location,
                        reachingDefinitions: new Set(),
                        liveVariables: new Set()
                    }))
                });
                // Update def-use chains
                for (const def of reachingForVar) {
                    if (!defUseChains.has(def.id)) {
                        defUseChains.set(def.id, {
                            definition: {
                                id: def.id,
                                variable: def.variable,
                                type: 'definition',
                                location: def.location,
                                reachingDefinitions: new Set(),
                                liveVariables: new Set()
                            },
                            uses: []
                        });
                    }
                    defUseChains.get(def.id).uses.push(useDfgNode);
                }
            }
        }
        return { defUseChains, useDefChains };
    }
    // ========================================================================
    // Phase 4: Build DFG Nodes
    // ========================================================================
    buildDFGNodes(reachingDefs) {
        const nodes = new Map();
        // Add definition nodes
        for (const defs of this.definitions.values()) {
            for (const def of defs) {
                nodes.set(def.id, {
                    id: def.id,
                    variable: def.variable,
                    type: 'definition',
                    location: def.location,
                    reachingDefinitions: new Set(),
                    liveVariables: new Set()
                });
            }
        }
        // Add use nodes with reaching definitions
        for (const [cfgNodeId, uses] of this.cfgToUsesMap) {
            const reaching = reachingDefs.get(cfgNodeId) || new Set();
            for (const use of uses) {
                nodes.set(use.id, {
                    id: use.id,
                    variable: use.variable,
                    type: 'use',
                    location: use.location,
                    reachingDefinitions: new Set([...reaching].filter(defId => {
                        const allDefs = this.definitions.get(use.variable) || [];
                        return allDefs.some(d => d.id === defId);
                    })),
                    liveVariables: new Set()
                });
            }
        }
        return nodes;
    }
}
exports.DFGBuilder = DFGBuilder;
// ============================================================================
// Data Flow Analysis Utilities
// ============================================================================
class DFGAnalyzer {
    /**
     * Find all uses of a variable that are reachable from a definition
     */
    static findUsesOfDefinition(dfg, defId) {
        const chain = dfg.defUseChains.get(defId);
        return chain ? chain.uses : [];
    }
    /**
     * Find all definitions that may reach a use
     */
    static findDefinitionsForUse(dfg, useId) {
        const chain = dfg.useDefChains.get(useId);
        return chain ? chain.definitions : [];
    }
    /**
     * Check if a variable is defined before use at a given point
     */
    static isDefinedBeforeUse(dfg, useId) {
        const chain = dfg.useDefChains.get(useId);
        return chain !== undefined && chain.definitions.length > 0;
    }
    /**
     * Find unused definitions (definitions with no uses)
     */
    static findUnusedDefinitions(dfg) {
        const unused = [];
        for (const [defId, chain] of dfg.defUseChains) {
            if (chain.uses.length === 0) {
                unused.push(chain.definition);
            }
        }
        return unused;
    }
    /**
     * Find undefined uses (uses with no reaching definitions)
     */
    static findUndefinedUses(dfg) {
        const undefined = [];
        for (const node of dfg.nodes.values()) {
            if (node.type === 'use' && node.reachingDefinitions.size === 0) {
                undefined.push(node);
            }
        }
        return undefined;
    }
    /**
     * Trace the flow of data from a definition to all its uses
     */
    static traceDataFlow(dfg, startDefId, maxDepth = 10) {
        const paths = [];
        const startDef = dfg.defUseChains.get(startDefId)?.definition;
        if (!startDef)
            return paths;
        function trace(current, path, depth) {
            if (depth > maxDepth)
                return;
            path.push(current);
            if (current.type === 'use') {
                // Found a use - this is a complete path
                paths.push([...path]);
                // Check if this use is reassigned and trace further
                // This would require linking uses to subsequent definitions
            }
            else if (current.type === 'definition') {
                // Find uses of this definition
                const chain = dfg.defUseChains.get(current.id);
                if (chain) {
                    for (const use of chain.uses) {
                        trace(use, path, depth + 1);
                    }
                }
            }
            path.pop();
        }
        trace(startDef, [], 0);
        return paths;
    }
}
exports.DFGAnalyzer = DFGAnalyzer;
//# sourceMappingURL=dfgBuilder.js.map