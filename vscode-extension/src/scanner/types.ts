/**
 * Enhanced Security Scanner - Core Types and Interfaces
 *
 * This module defines the unified Intermediate Representation (IR) that all
 * language parsers emit, enabling cross-language security analysis.
 */

// ============================================================================
// Language Support
// ============================================================================

export type SupportedLanguage =
    | 'javascript'
    | 'typescript'
    | 'python'
    | 'java'
    | 'csharp'
    | 'php'
    | 'kotlin'
    | 'objectivec'
    | 'swift'
    | 'go'
    | 'ruby';

export interface LanguageConfig {
    id: SupportedLanguage;
    extensions: string[];
    parser: string;
    commentStyles: CommentStyle[];
}

export interface CommentStyle {
    single?: string;
    multiStart?: string;
    multiEnd?: string;
}

// ============================================================================
// Source Location
// ============================================================================

export interface SourceLocation {
    file: string;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
}

export interface SourceRange {
    start: Position;
    end: Position;
}

export interface Position {
    line: number;
    column: number;
    offset?: number;
}

// ============================================================================
// Unified IR Node Types
// ============================================================================

export type IRNodeType =
    // Program structure
    | 'Program'
    | 'Module'
    | 'Class'
    | 'Interface'
    | 'Function'
    | 'Method'
    | 'Constructor'
    | 'Property'
    | 'Parameter'
    // Statements
    | 'VariableDeclaration'
    | 'Assignment'
    | 'Return'
    | 'If'
    | 'Switch'
    | 'Case'
    | 'For'
    | 'ForEach'
    | 'While'
    | 'DoWhile'
    | 'Try'
    | 'Catch'
    | 'Finally'
    | 'Throw'
    | 'Break'
    | 'Continue'
    | 'Block'
    // Expressions
    | 'BinaryExpression'
    | 'UnaryExpression'
    | 'CallExpression'
    | 'MemberExpression'
    | 'IndexExpression'
    | 'NewExpression'
    | 'ConditionalExpression'
    | 'ArrowFunction'
    | 'Lambda'
    // Literals
    | 'StringLiteral'
    | 'NumberLiteral'
    | 'BooleanLiteral'
    | 'NullLiteral'
    | 'ArrayLiteral'
    | 'ObjectLiteral'
    | 'TemplateLiteral'
    // Identifiers
    | 'Identifier'
    | 'QualifiedName'
    // Imports/Exports
    | 'Import'
    | 'Export'
    // Other
    | 'Comment'
    | 'Unknown';

// ============================================================================
// IR Base Node
// ============================================================================

export interface IRNode {
    type: IRNodeType;
    location: SourceLocation;
    children?: IRNode[];
    parent?: IRNode;
    metadata?: Record<string, unknown>;
    // Common optional properties used by various node types
    name?: string;
    value?: string | number | boolean;
    raw?: string;
    callee?: IRNode;
    object?: IRNode;
    property?: IRNode;
    operator?: string;
    quasis?: IRNode[];
    expressions?: IRNode[];
    arguments?: IRNode[];
    computed?: boolean;
    left?: IRNode;
    right?: IRNode;
}

// ============================================================================
// Program Structure Nodes
// ============================================================================

export interface ProgramNode extends IRNode {
    type: 'Program';
    language: SupportedLanguage;
    imports: ImportNode[];
    body: IRNode[];
    exports: ExportNode[];
}

export interface ClassNode extends IRNode {
    type: 'Class';
    name: string;
    superClass?: string;
    interfaces?: string[];
    modifiers: Modifier[];
    members: (MethodNode | PropertyNode | ConstructorNode)[];
    isAbstract?: boolean;
}

export interface InterfaceNode extends IRNode {
    type: 'Interface';
    name: string;
    extends?: string[];
    members: (MethodNode | PropertyNode)[];
}

export interface FunctionNode extends IRNode {
    type: 'Function';
    name: string;
    parameters: ParameterNode[];
    returnType?: TypeInfo;
    body: BlockNode;
    modifiers: Modifier[];
    isAsync?: boolean;
    isGenerator?: boolean;
}

export interface MethodNode extends IRNode {
    type: 'Method';
    name: string;
    parameters: ParameterNode[];
    returnType?: TypeInfo;
    body?: BlockNode;
    modifiers: Modifier[];
    isAsync?: boolean;
    isStatic?: boolean;
    isAbstract?: boolean;
}

export interface ConstructorNode extends IRNode {
    type: 'Constructor';
    parameters: ParameterNode[];
    body: BlockNode;
    modifiers: Modifier[];
}

export interface PropertyNode extends IRNode {
    type: 'Property';
    name: string;
    valueType?: TypeInfo;
    initializer?: IRNode;
    modifiers: Modifier[];
    isStatic?: boolean;
}

export interface ParameterNode extends IRNode {
    type: 'Parameter';
    name: string;
    paramType?: TypeInfo;
    defaultValue?: IRNode;
    isOptional?: boolean;
    isRest?: boolean;
}

// ============================================================================
// Statement Nodes
// ============================================================================

export interface BlockNode extends IRNode {
    type: 'Block';
    statements: IRNode[];
}

export interface VariableDeclarationNode extends IRNode {
    type: 'VariableDeclaration';
    name: string;
    varType?: TypeInfo;
    initializer?: IRNode;
    kind: 'const' | 'let' | 'var' | 'final' | 'val';
}

export interface AssignmentNode extends IRNode {
    type: 'Assignment';
    left: IRNode;
    right: IRNode;
    operator: string;
}

export interface IfNode extends IRNode {
    type: 'If';
    condition: IRNode;
    thenBranch: BlockNode;
    elseBranch?: BlockNode | IfNode;
}

export interface SwitchNode extends IRNode {
    type: 'Switch';
    discriminant: IRNode;
    cases: CaseNode[];
}

export interface CaseNode extends IRNode {
    type: 'Case';
    test: IRNode | null; // null for default case
    consequent: IRNode[];
}

export interface ForNode extends IRNode {
    type: 'For';
    init?: IRNode;
    test?: IRNode;
    update?: IRNode;
    body: BlockNode;
}

export interface ForEachNode extends IRNode {
    type: 'ForEach';
    variable: IRNode;
    iterable: IRNode;
    body: BlockNode;
}

export interface WhileNode extends IRNode {
    type: 'While';
    test: IRNode;
    body: BlockNode;
}

export interface TryNode extends IRNode {
    type: 'Try';
    body: BlockNode;
    handlers: CatchNode[];
    finalizer?: BlockNode;
}

export interface CatchNode extends IRNode {
    type: 'Catch';
    param?: ParameterNode;
    body: BlockNode;
}

export interface ReturnNode extends IRNode {
    type: 'Return';
    argument?: IRNode;
}

export interface ThrowNode extends IRNode {
    type: 'Throw';
    argument: IRNode;
}

// ============================================================================
// Expression Nodes
// ============================================================================

export interface BinaryExpressionNode extends IRNode {
    type: 'BinaryExpression';
    operator: string;
    left: IRNode;
    right: IRNode;
}

export interface UnaryExpressionNode extends IRNode {
    type: 'UnaryExpression';
    operator: string;
    argument: IRNode;
    prefix: boolean;
}

export interface CallExpressionNode extends IRNode {
    type: 'CallExpression';
    callee: IRNode;
    arguments: IRNode[];
    isOptional?: boolean;
}

export interface MemberExpressionNode extends IRNode {
    type: 'MemberExpression';
    object: IRNode;
    property: IRNode;
    computed: boolean;
    isOptional?: boolean;
}

export interface IndexExpressionNode extends IRNode {
    type: 'IndexExpression';
    object: IRNode;
    index: IRNode;
}

export interface NewExpressionNode extends IRNode {
    type: 'NewExpression';
    callee: IRNode;
    arguments: IRNode[];
}

export interface ConditionalExpressionNode extends IRNode {
    type: 'ConditionalExpression';
    test: IRNode;
    consequent: IRNode;
    alternate: IRNode;
}

// ============================================================================
// Literal Nodes
// ============================================================================

export interface StringLiteralNode extends IRNode {
    type: 'StringLiteral';
    value: string;
    raw: string;
}

export interface NumberLiteralNode extends IRNode {
    type: 'NumberLiteral';
    value: number;
    raw: string;
}

export interface BooleanLiteralNode extends IRNode {
    type: 'BooleanLiteral';
    value: boolean;
}

export interface NullLiteralNode extends IRNode {
    type: 'NullLiteral';
}

export interface ArrayLiteralNode extends IRNode {
    type: 'ArrayLiteral';
    elements: IRNode[];
}

export interface ObjectLiteralNode extends IRNode {
    type: 'ObjectLiteral';
    properties: PropertyNode[];
}

export interface TemplateLiteralNode extends IRNode {
    type: 'TemplateLiteral';
    quasis: StringLiteralNode[];
    expressions: IRNode[];
}

// ============================================================================
// Identifier Nodes
// ============================================================================

export interface IdentifierNode extends IRNode {
    type: 'Identifier';
    name: string;
}

export interface QualifiedNameNode extends IRNode {
    type: 'QualifiedName';
    parts: string[];
}

// ============================================================================
// Import/Export Nodes
// ============================================================================

export interface ImportNode extends IRNode {
    type: 'Import';
    source: string;
    specifiers: ImportSpecifier[];
    isDefault?: boolean;
    isNamespace?: boolean;
}

export interface ImportSpecifier {
    local: string;
    imported: string;
}

export interface ExportNode extends IRNode {
    type: 'Export';
    declaration?: IRNode;
    specifiers?: ExportSpecifier[];
    source?: string;
    isDefault?: boolean;
}

export interface ExportSpecifier {
    local: string;
    exported: string;
}

// ============================================================================
// Type Information
// ============================================================================

export interface TypeInfo {
    name: string;
    isArray?: boolean;
    isNullable?: boolean;
    isOptional?: boolean;
    genericArgs?: TypeInfo[];
    unionTypes?: TypeInfo[];
}

export type Modifier =
    | 'public'
    | 'private'
    | 'protected'
    | 'internal'
    | 'static'
    | 'final'
    | 'abstract'
    | 'readonly'
    | 'const'
    | 'async'
    | 'override'
    | 'virtual';

// ============================================================================
// Symbol Table
// ============================================================================

export interface Symbol {
    name: string;
    kind: SymbolKind;
    type?: TypeInfo;
    scope: Scope;
    declaration: SourceLocation;
    references: SourceLocation[];
    modifiers: Modifier[];
}

export type SymbolKind =
    | 'variable'
    | 'function'
    | 'class'
    | 'interface'
    | 'method'
    | 'property'
    | 'parameter'
    | 'enum'
    | 'module'
    | 'namespace';

export interface Scope {
    id: string;
    parent?: Scope;
    children: Scope[];
    symbols: Map<string, Symbol>;
    kind: ScopeKind;
}

export type ScopeKind =
    | 'global'
    | 'module'
    | 'class'
    | 'function'
    | 'block'
    | 'catch'
    | 'loop';

// ============================================================================
// Control Flow Graph (CFG)
// ============================================================================

export interface CFGNode {
    id: string;
    type: CFGNodeType;
    astNode?: IRNode;
    predecessors: CFGNode[];
    successors: CFGNode[];
    dominators?: Set<string>;
    postDominators?: Set<string>;
}

export type CFGNodeType =
    | 'entry'
    | 'exit'
    | 'basic'
    | 'branch'
    | 'merge'
    | 'loop-header'
    | 'loop-exit'
    | 'try'
    | 'catch'
    | 'finally'
    | 'throw'
    | 'return';

export interface ControlFlowGraph {
    entry: CFGNode;
    exit: CFGNode;
    nodes: Map<string, CFGNode>;
    edges: CFGEdge[];
}

export interface CFGEdge {
    from: string;
    to: string;
    type: CFGEdgeType;
    condition?: IRNode;
}

export type CFGEdgeType =
    | 'unconditional'
    | 'true-branch'
    | 'false-branch'
    | 'exception'
    | 'fallthrough';

// ============================================================================
// Data Flow Graph (DFG)
// ============================================================================

export interface DFGNode {
    id: string;
    variable: string;
    type: DFGNodeType;
    location: SourceLocation;
    reachingDefinitions: Set<string>;
    liveVariables: Set<string>;
}

export type DFGNodeType =
    | 'definition'
    | 'use'
    | 'phi'
    | 'parameter'
    | 'return';

export interface DataFlowGraph {
    nodes: Map<string, DFGNode>;
    defUseChains: Map<string, DefUseChain>;
    useDefChains: Map<string, UseDefChain>;
}

export interface DefUseChain {
    definition: DFGNode;
    uses: DFGNode[];
}

export interface UseDefChain {
    use: DFGNode;
    definitions: DFGNode[];
}

// ============================================================================
// Taint Analysis
// ============================================================================

export interface TaintSource {
    id: string;
    name: string;
    category: TaintSourceCategory;
    pattern: TaintPattern;
    description: string;
}

export type TaintSourceCategory =
    | 'user-input'
    | 'file-read'
    | 'network-input'
    | 'database-read'
    | 'environment'
    | 'external-api';

export interface TaintSink {
    id: string;
    name: string;
    category: TaintSinkCategory;
    pattern: TaintPattern;
    vulnerabilityType: VulnerabilityType;
    description: string;
}

export type TaintSinkCategory =
    | 'sql-query'
    | 'command-execution'
    | 'file-operation'
    | 'html-output'
    | 'url-redirect'
    | 'deserialization'
    | 'code-execution'
    | 'ldap-query'
    | 'xpath-query'
    | 'xml-parse';

export interface TaintPropagator {
    id: string;
    name: string;
    pattern: TaintPattern;
    propagationType: PropagationType;
}

export type PropagationType =
    | 'passthrough'  // Taint passes through unchanged
    | 'sanitizer'    // Removes taint
    | 'transformer'  // Modifies taint (e.g., encoding)
    | 'combiner';    // Combines multiple tainted values

export interface TaintPattern {
    type: 'method-call' | 'property-access' | 'function-call' | 'constructor';
    className?: string;
    methodName?: string;
    propertyName?: string;
    functionName?: string;
    argumentIndex?: number;
    returnValue?: boolean;
}

export interface TaintedValue {
    variable: string;
    source: TaintSource;
    location: SourceLocation;
    path: TaintPathNode[];
}

export interface TaintPathNode {
    location: SourceLocation;
    description: string;
    node: IRNode;
}

export interface TaintFlow {
    source: TaintSource;
    sink: TaintSink;
    taintedValue: TaintedValue;
    path: TaintPathNode[];
    sanitizers: TaintPropagator[];
}

// ============================================================================
// Vulnerability Types
// ============================================================================

export type VulnerabilityType =
    | 'sql-injection'
    | 'xss'
    | 'command-injection'
    | 'path-traversal'
    | 'xxe'
    | 'ssrf'
    | 'deserialization'
    | 'code-injection'
    | 'ldap-injection'
    | 'xpath-injection'
    | 'open-redirect'
    | 'hardcoded-secret'
    | 'weak-crypto'
    | 'insecure-random'
    | 'missing-auth'
    | 'broken-access-control';

// ============================================================================
// Analysis Results
// ============================================================================

export interface AnalysisResult {
    file: string;
    language: SupportedLanguage;
    program: ProgramNode;
    symbolTable: Scope;
    cfg: Map<string, ControlFlowGraph>;
    dfg: DataFlowGraph;
    findings: SecurityFinding[];
    metrics: CodeMetrics;
    analysisTime: number;
}

export interface SecurityFinding {
    id: string;
    type: VulnerabilityType;
    severity: Severity;
    title: string;
    description: string;
    location: SourceLocation;
    cweId?: string;
    owaspCategory?: string;
    taintFlow?: TaintFlow;
    codeSnippet: string;
    recommendation: string;
    confidence: Confidence;
    metadata?: Record<string, unknown>;
    fix?: {
        code: string;
        description?: string;
    };
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export interface CodeMetrics {
    linesOfCode: number;
    cyclomaticComplexity: number;
    numberOfFunctions: number;
    numberOfClasses: number;
    maxNestingDepth: number;
}

// ============================================================================
// Parser Interface
// ============================================================================

export interface LanguageParser {
    language: SupportedLanguage;
    supportedExtensions: string[];

    parse(source: string, filePath: string): Promise<ProgramNode>;
    buildSymbolTable(program: ProgramNode): Scope;
}

// ============================================================================
// Analysis Engine Interface
// ============================================================================

export interface AnalysisEngine {
    analyze(program: ProgramNode, symbolTable: Scope): Promise<AnalysisResult>;
}

export interface CFGBuilder {
    build(func: FunctionNode | MethodNode): ControlFlowGraph;
}

export interface DFGBuilder {
    build(cfg: ControlFlowGraph, symbolTable: Scope): DataFlowGraph;
}

export interface TaintAnalyzer {
    analyze(
        program: ProgramNode,
        cfg: Map<string, ControlFlowGraph>,
        dfg: DataFlowGraph
    ): TaintFlow[];
}
