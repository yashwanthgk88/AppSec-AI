/**
 * Taint Analysis Engine
 *
 * Performs interprocedural taint analysis to track the flow of untrusted data
 * from sources (user inputs) to sinks (security-sensitive operations).
 */

import {
    ProgramNode,
    ControlFlowGraph,
    DataFlowGraph,
    TaintFlow,
    TaintSource,
    TaintSink,
    TaintPropagator,
    TaintedValue,
    TaintPathNode,
    IRNode,
    CallExpressionNode,
    MemberExpressionNode,
    IdentifierNode,
    AssignmentNode,
    VariableDeclarationNode,
    FunctionNode,
    MethodNode,
    SourceLocation,
    SupportedLanguage
} from '../types';

import {
    TAINT_SOURCES,
    TAINT_SINKS,
    TAINT_PROPAGATORS,
    getSourcesForLanguage,
    getSinksForLanguage
} from '../taintRules';

interface TaintState {
    taintedVars: Map<string, TaintedValue>;
    currentPath: TaintPathNode[];
}

interface TaintMatch {
    source?: TaintSource;
    sink?: TaintSink;
    propagator?: TaintPropagator;
    node: IRNode;
    variable?: string;
}

export class TaintAnalyzer {
    private language: SupportedLanguage;
    private sources: TaintSource[];
    private sinks: TaintSink[];
    private propagators: TaintPropagator[];
    private flows: TaintFlow[] = [];

    constructor(language: SupportedLanguage) {
        this.language = language;
        this.sources = getSourcesForLanguage(language);
        this.sinks = getSinksForLanguage(language);
        this.propagators = TAINT_PROPAGATORS;
    }

    /**
     * Analyze a program for taint flows
     */
    analyze(
        program: ProgramNode,
        cfgMap: Map<string, ControlFlowGraph>,
        dfg: DataFlowGraph
    ): TaintFlow[] {
        this.flows = [];

        // Analyze each function/method
        for (const node of program.body) {
            if (node.type === 'Function' || node.type === 'Method') {
                this.analyzeFunction(node as FunctionNode | MethodNode, cfgMap, dfg);
            } else if (node.type === 'Class') {
                const classNode = node as any;
                for (const member of classNode.members) {
                    if (member.type === 'Method' || member.type === 'Constructor') {
                        this.analyzeFunction(member, cfgMap, dfg);
                    }
                }
            }
        }

        // Also analyze top-level statements (for scripts)
        this.analyzeStatements(program.body, dfg);

        return this.flows;
    }

    private analyzeFunction(
        func: FunctionNode | MethodNode,
        cfgMap: Map<string, ControlFlowGraph>,
        dfg: DataFlowGraph
    ): void {
        const state: TaintState = {
            taintedVars: new Map(),
            currentPath: []
        };

        // Parameters are potential taint sources
        for (const param of func.parameters) {
            // Check if parameter receives tainted data (e.g., request object)
            const sourceMatch = this.matchSource(param);
            if (sourceMatch) {
                state.taintedVars.set(param.name, {
                    variable: param.name,
                    source: sourceMatch,
                    location: param.location,
                    path: [{
                        location: param.location,
                        description: `Parameter '${param.name}' receives tainted data`,
                        node: param
                    }]
                });
            }
        }

        // Analyze function body
        if (func.body) {
            this.analyzeBlock(func.body.statements, state, dfg);
        }
    }

    private analyzeStatements(
        statements: IRNode[],
        dfg: DataFlowGraph
    ): void {
        const state: TaintState = {
            taintedVars: new Map(),
            currentPath: []
        };

        this.analyzeBlock(statements, state, dfg);
    }

    private analyzeBlock(
        statements: IRNode[],
        state: TaintState,
        dfg: DataFlowGraph
    ): void {
        for (const stmt of statements) {
            this.analyzeStatement(stmt, state, dfg);
        }
    }

    private analyzeStatement(
        stmt: IRNode,
        state: TaintState,
        dfg: DataFlowGraph
    ): void {
        switch (stmt.type) {
            case 'VariableDeclaration':
                this.analyzeVariableDeclaration(stmt as VariableDeclarationNode, state);
                break;

            case 'Assignment':
                this.analyzeAssignment(stmt as AssignmentNode, state);
                break;

            case 'CallExpression':
                this.analyzeCallExpression(stmt as CallExpressionNode, state);
                break;

            case 'If':
                const ifStmt = stmt as any;
                this.analyzeBlock(ifStmt.thenBranch.statements, { ...state, taintedVars: new Map(state.taintedVars) }, dfg);
                if (ifStmt.elseBranch) {
                    if (ifStmt.elseBranch.type === 'Block') {
                        this.analyzeBlock(ifStmt.elseBranch.statements, { ...state, taintedVars: new Map(state.taintedVars) }, dfg);
                    } else {
                        this.analyzeStatement(ifStmt.elseBranch, { ...state, taintedVars: new Map(state.taintedVars) }, dfg);
                    }
                }
                break;

            case 'For':
            case 'ForEach':
            case 'While':
            case 'DoWhile':
                const loopStmt = stmt as any;
                this.analyzeBlock(loopStmt.body.statements, { ...state, taintedVars: new Map(state.taintedVars) }, dfg);
                break;

            case 'Try':
                const tryStmt = stmt as any;
                this.analyzeBlock(tryStmt.body.statements, { ...state, taintedVars: new Map(state.taintedVars) }, dfg);
                for (const handler of tryStmt.handlers) {
                    this.analyzeBlock(handler.body.statements, { ...state, taintedVars: new Map(state.taintedVars) }, dfg);
                }
                if (tryStmt.finalizer) {
                    this.analyzeBlock(tryStmt.finalizer.statements, state, dfg);
                }
                break;

            case 'Return':
                const returnStmt = stmt as any;
                if (returnStmt.argument) {
                    // Check if returning tainted data
                    this.checkExpression(returnStmt.argument, state);
                }
                break;

            case 'Block':
                this.analyzeBlock((stmt as any).statements, state, dfg);
                break;

            default:
                // For expressions, check for taint
                this.checkExpression(stmt, state);
                break;
        }
    }

    private analyzeVariableDeclaration(
        decl: VariableDeclarationNode,
        state: TaintState
    ): void {
        if (!decl.initializer) return;

        // Check if initializer is a taint source
        const sourceMatch = this.findTaintSource(decl.initializer, state);
        if (sourceMatch) {
            state.taintedVars.set(decl.name, sourceMatch);
            return;
        }

        // Check if initializer uses tainted variables
        const taintedValue = this.checkForTaintedValue(decl.initializer, state);
        if (taintedValue) {
            // Propagate taint
            const newTainted: TaintedValue = {
                ...taintedValue,
                variable: decl.name,
                path: [
                    ...taintedValue.path,
                    {
                        location: decl.location,
                        description: `Taint propagated to '${decl.name}'`,
                        node: decl
                    }
                ]
            };
            state.taintedVars.set(decl.name, newTainted);
        }

        // Check if initializer is a sink
        this.checkForSink(decl.initializer, state);
    }

    private analyzeAssignment(
        assign: AssignmentNode,
        state: TaintState
    ): void {
        const targetVar = this.getVariableName(assign.left);
        if (!targetVar) return;

        // Check if right side is a taint source
        const sourceMatch = this.findTaintSource(assign.right, state);
        if (sourceMatch) {
            state.taintedVars.set(targetVar, sourceMatch);
            return;
        }

        // Check if right side uses tainted variables
        const taintedValue = this.checkForTaintedValue(assign.right, state);
        if (taintedValue) {
            // Check for sanitizer
            const sanitizer = this.checkForSanitizer(assign.right);
            if (sanitizer) {
                // Taint is sanitized
                state.taintedVars.delete(targetVar);
                return;
            }

            // Propagate taint
            const newTainted: TaintedValue = {
                ...taintedValue,
                variable: targetVar,
                path: [
                    ...taintedValue.path,
                    {
                        location: assign.location,
                        description: `Taint propagated to '${targetVar}'`,
                        node: assign
                    }
                ]
            };
            state.taintedVars.set(targetVar, newTainted);
        } else {
            // Right side is not tainted, remove taint from target
            state.taintedVars.delete(targetVar);
        }

        // Check if right side reaches a sink
        this.checkForSink(assign.right, state);
    }

    private analyzeCallExpression(
        call: CallExpressionNode,
        state: TaintState
    ): void {
        // Check if this call is a sink
        this.checkForSink(call, state);

        // Check if this call is a source
        const sourceMatch = this.findTaintSource(call, state);
        if (sourceMatch) {
            // If call result is assigned to a variable, that's handled in assignment
            // Here we just note that the call itself produces tainted data
        }

        // Check arguments for tainted values flowing to sinks
        for (const arg of call.arguments) {
            this.checkExpression(arg, state);
        }
    }

    private checkExpression(expr: IRNode, state: TaintState): void {
        if (!expr) return;

        // Check if this expression is a sink
        this.checkForSink(expr, state);

        // Recursively check sub-expressions
        switch (expr.type) {
            case 'CallExpression':
                const call = expr as CallExpressionNode;
                this.checkExpression(call.callee, state);
                for (const arg of call.arguments) {
                    this.checkExpression(arg, state);
                }
                break;

            case 'MemberExpression':
                const member = expr as MemberExpressionNode;
                this.checkExpression(member.object, state);
                break;

            case 'BinaryExpression':
                const binary = expr as any;
                this.checkExpression(binary.left, state);
                this.checkExpression(binary.right, state);
                break;

            case 'ArrayLiteral':
                const array = expr as any;
                for (const elem of array.elements) {
                    this.checkExpression(elem, state);
                }
                break;

            case 'ObjectLiteral':
                const obj = expr as any;
                for (const prop of obj.properties) {
                    if (prop.initializer) {
                        this.checkExpression(prop.initializer, state);
                    }
                }
                break;
        }
    }

    // ========================================================================
    // Taint Source Detection
    // ========================================================================

    private findTaintSource(expr: IRNode, state: TaintState): TaintedValue | null {
        // Check for direct source match
        const source = this.matchSourceExpression(expr);
        if (source) {
            return {
                variable: this.getVariableName(expr) || '<expression>',
                source,
                location: expr.location,
                path: [{
                    location: expr.location,
                    description: `Taint source: ${source.name}`,
                    node: expr
                }]
            };
        }

        // Check for member access on tainted object
        if (expr.type === 'MemberExpression') {
            const member = expr as MemberExpressionNode;
            const baseVar = this.getVariableName(member.object);
            if (baseVar && state.taintedVars.has(baseVar)) {
                return state.taintedVars.get(baseVar)!;
            }
        }

        return null;
    }

    private matchSourceExpression(expr: IRNode): TaintSource | null {
        for (const source of this.sources) {
            if (this.matchPattern(expr, source.pattern)) {
                return source;
            }
        }
        return null;
    }

    private matchSource(node: IRNode): TaintSource | null {
        // Check parameter names that commonly receive tainted data
        if (node.type === 'Parameter') {
            const param = node as any;
            const name = param.name.toLowerCase();

            // Common parameter names that receive user input
            const taintedParamPatterns = [
                'req', 'request', 'body', 'params', 'query',
                'input', 'data', 'payload', 'form'
            ];

            if (taintedParamPatterns.some(p => name.includes(p))) {
                return {
                    id: 'param-source',
                    name: `Parameter ${param.name}`,
                    category: 'user-input',
                    pattern: { type: 'property-access', propertyName: param.name },
                    description: `Parameter '${param.name}' may receive untrusted input`
                };
            }
        }

        return null;
    }

    // ========================================================================
    // Taint Sink Detection
    // ========================================================================

    private checkForSink(expr: IRNode, state: TaintState): void {
        const sink = this.matchSinkExpression(expr);
        if (!sink) return;

        // Check if any tainted value flows to this sink
        const taintedValue = this.checkForTaintedValue(expr, state);
        if (!taintedValue) return;

        // Check for sanitizers in the path
        const sanitizers = this.findSanitizersInExpression(expr);

        // Record the taint flow
        this.flows.push({
            source: taintedValue.source,
            sink,
            taintedValue,
            path: [
                ...taintedValue.path,
                {
                    location: expr.location,
                    description: `Taint flows to sink: ${sink.name}`,
                    node: expr
                }
            ],
            sanitizers
        });
    }

    private matchSinkExpression(expr: IRNode): TaintSink | null {
        for (const sink of this.sinks) {
            if (this.matchPattern(expr, sink.pattern)) {
                return sink;
            }
        }
        return null;
    }

    // ========================================================================
    // Taint Propagation
    // ========================================================================

    private checkForTaintedValue(expr: IRNode, state: TaintState): TaintedValue | null {
        if (!expr) return null;

        switch (expr.type) {
            case 'Identifier':
                const ident = expr as IdentifierNode;
                return state.taintedVars.get(ident.name) || null;

            case 'MemberExpression':
                const member = expr as MemberExpressionNode;
                // Check the base object
                const baseTaint = this.checkForTaintedValue(member.object, state);
                if (baseTaint) return baseTaint;
                // Check full path
                const fullPath = this.getVariableName(member);
                if (fullPath && state.taintedVars.has(fullPath)) {
                    return state.taintedVars.get(fullPath)!;
                }
                return null;

            case 'CallExpression':
                const call = expr as CallExpressionNode;
                // Check if any argument is tainted
                for (const arg of call.arguments) {
                    const argTaint = this.checkForTaintedValue(arg, state);
                    if (argTaint) {
                        // Check if this call is a sanitizer
                        const sanitizer = this.checkForSanitizer(call);
                        if (sanitizer) {
                            return null; // Sanitized
                        }
                        return argTaint;
                    }
                }
                // Check if callee is tainted
                return this.checkForTaintedValue(call.callee, state);

            case 'BinaryExpression':
                const binary = expr as any;
                // If either operand is tainted, result is tainted
                const leftTaint = this.checkForTaintedValue(binary.left, state);
                if (leftTaint) return leftTaint;
                return this.checkForTaintedValue(binary.right, state);

            case 'TemplateLiteral':
                const template = expr as any;
                for (const exp of template.expressions) {
                    const taint = this.checkForTaintedValue(exp, state);
                    if (taint) return taint;
                }
                return null;

            case 'ArrayLiteral':
                const array = expr as any;
                for (const elem of array.elements) {
                    const taint = this.checkForTaintedValue(elem, state);
                    if (taint) return taint;
                }
                return null;

            default:
                return null;
        }
    }

    // ========================================================================
    // Sanitizer Detection
    // ========================================================================

    private checkForSanitizer(expr: IRNode): TaintPropagator | null {
        if (expr.type !== 'CallExpression') return null;

        for (const prop of this.propagators) {
            if (prop.propagationType === 'sanitizer' && this.matchPattern(expr, prop.pattern)) {
                return prop;
            }
        }

        return null;
    }

    private findSanitizersInExpression(expr: IRNode): TaintPropagator[] {
        const sanitizers: TaintPropagator[] = [];

        const traverse = (node: IRNode): void => {
            const sanitizer = this.checkForSanitizer(node);
            if (sanitizer) {
                sanitizers.push(sanitizer);
            }

            // Traverse children
            if (node.type === 'CallExpression') {
                const call = node as CallExpressionNode;
                traverse(call.callee);
                for (const arg of call.arguments) {
                    traverse(arg);
                }
            } else if (node.type === 'MemberExpression') {
                const member = node as MemberExpressionNode;
                traverse(member.object);
            }
        };

        traverse(expr);
        return sanitizers;
    }

    // ========================================================================
    // Pattern Matching
    // ========================================================================

    private matchPattern(expr: IRNode, pattern: any): boolean {
        switch (pattern.type) {
            case 'function-call':
                return this.matchFunctionCall(expr, pattern);
            case 'method-call':
                return this.matchMethodCall(expr, pattern);
            case 'property-access':
                return this.matchPropertyAccess(expr, pattern);
            case 'constructor':
                return this.matchConstructor(expr, pattern);
            default:
                return false;
        }
    }

    private matchFunctionCall(expr: IRNode, pattern: any): boolean {
        if (expr.type !== 'CallExpression') return false;

        const call = expr as CallExpressionNode;
        if (call.callee.type === 'Identifier') {
            const ident = call.callee as IdentifierNode;
            return ident.name === pattern.functionName;
        }

        return false;
    }

    private matchMethodCall(expr: IRNode, pattern: any): boolean {
        if (expr.type !== 'CallExpression') return false;

        const call = expr as CallExpressionNode;
        if (call.callee.type === 'MemberExpression') {
            const member = call.callee as MemberExpressionNode;
            if (member.property.type === 'Identifier') {
                const propName = (member.property as IdentifierNode).name;

                // Check method name
                if (propName !== pattern.methodName) return false;

                // Check class name if specified
                if (pattern.className) {
                    if (member.object.type === 'Identifier') {
                        const objName = (member.object as IdentifierNode).name;
                        return objName === pattern.className;
                    }
                    return false;
                }

                return true;
            }
        }

        return false;
    }

    private matchPropertyAccess(expr: IRNode, pattern: any): boolean {
        if (expr.type === 'MemberExpression') {
            const member = expr as MemberExpressionNode;
            if (member.property.type === 'Identifier') {
                const propName = (member.property as IdentifierNode).name;
                return propName === pattern.propertyName;
            }
        }

        // Also check assignments to properties
        if (expr.type === 'Assignment') {
            const assign = expr as AssignmentNode;
            if (assign.left.type === 'MemberExpression') {
                const member = assign.left as MemberExpressionNode;
                if (member.property.type === 'Identifier') {
                    const propName = (member.property as IdentifierNode).name;
                    return propName === pattern.propertyName;
                }
            }
        }

        return false;
    }

    private matchConstructor(expr: IRNode, pattern: any): boolean {
        if (expr.type !== 'NewExpression') return false;

        const newExpr = expr as any;
        if (newExpr.callee.type === 'Identifier') {
            const className = (newExpr.callee as IdentifierNode).name;
            return className === pattern.className;
        }

        return false;
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    private getVariableName(expr: IRNode): string | null {
        if (expr.type === 'Identifier') {
            return (expr as IdentifierNode).name;
        }
        if (expr.type === 'MemberExpression') {
            const member = expr as MemberExpressionNode;
            const base = this.getVariableName(member.object);
            if (base && member.property.type === 'Identifier') {
                return `${base}.${(member.property as IdentifierNode).name}`;
            }
        }
        return null;
    }
}

// ============================================================================
// Taint Analysis Utilities
// ============================================================================

export class TaintAnalysisUtils {
    /**
     * Generate a human-readable description of a taint flow
     */
    static describeTaintFlow(flow: TaintFlow): string {
        const lines: string[] = [];

        lines.push(`[${flow.sink.vulnerabilityType.toUpperCase()}] ${flow.sink.description}`);
        lines.push('');
        lines.push('Taint Flow:');

        for (let i = 0; i < flow.path.length; i++) {
            const node = flow.path[i];
            const prefix = i === 0 ? '├─ SOURCE: ' :
                          i === flow.path.length - 1 ? '└─ SINK: ' :
                          '│  → ';
            lines.push(`${prefix}${node.description}`);
            lines.push(`   at ${node.location.file}:${node.location.startLine}`);
        }

        if (flow.sanitizers.length > 0) {
            lines.push('');
            lines.push('⚠️ Potential sanitizers found (verify effectiveness):');
            for (const san of flow.sanitizers) {
                lines.push(`  - ${san.name}`);
            }
        }

        return lines.join('\n');
    }

    /**
     * Get severity for a vulnerability type
     */
    static getSeverityForVulnerability(vuln: string): 'critical' | 'high' | 'medium' | 'low' {
        const criticalVulns = ['sql-injection', 'command-injection', 'code-injection', 'deserialization'];
        const highVulns = ['xss', 'path-traversal', 'ssrf', 'xxe', 'ldap-injection'];
        const mediumVulns = ['open-redirect', 'xpath-injection'];

        if (criticalVulns.includes(vuln)) return 'critical';
        if (highVulns.includes(vuln)) return 'high';
        if (mediumVulns.includes(vuln)) return 'medium';
        return 'low';
    }

    /**
     * Get CWE ID for a vulnerability type
     */
    static getCWEForVulnerability(vuln: string): string {
        const cweMap: Record<string, string> = {
            'sql-injection': 'CWE-89',
            'xss': 'CWE-79',
            'command-injection': 'CWE-78',
            'path-traversal': 'CWE-22',
            'xxe': 'CWE-611',
            'ssrf': 'CWE-918',
            'deserialization': 'CWE-502',
            'code-injection': 'CWE-94',
            'ldap-injection': 'CWE-90',
            'xpath-injection': 'CWE-643',
            'open-redirect': 'CWE-601',
            'hardcoded-secret': 'CWE-798',
            'weak-crypto': 'CWE-327',
            'insecure-random': 'CWE-330'
        };

        return cweMap[vuln] || 'CWE-Unknown';
    }

    /**
     * Get OWASP category for a vulnerability type
     */
    static getOWASPCategory(vuln: string): string {
        const owaspMap: Record<string, string> = {
            'sql-injection': 'A03:2021 - Injection',
            'command-injection': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection',
            'code-injection': 'A03:2021 - Injection',
            'ldap-injection': 'A03:2021 - Injection',
            'xpath-injection': 'A03:2021 - Injection',
            'xxe': 'A05:2021 - Security Misconfiguration',
            'path-traversal': 'A01:2021 - Broken Access Control',
            'ssrf': 'A10:2021 - Server-Side Request Forgery',
            'deserialization': 'A08:2021 - Software and Data Integrity Failures',
            'open-redirect': 'A01:2021 - Broken Access Control',
            'hardcoded-secret': 'A02:2021 - Cryptographic Failures',
            'weak-crypto': 'A02:2021 - Cryptographic Failures',
            'insecure-random': 'A02:2021 - Cryptographic Failures'
        };

        return owaspMap[vuln] || 'Unknown';
    }
}
