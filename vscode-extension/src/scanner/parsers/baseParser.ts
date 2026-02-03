/**
 * Base Parser - Abstract interface for language-specific parsers
 *
 * Provides a unified interface for parsing source code into the IR format.
 * Language-specific parsers extend this class.
 */

import {
    SupportedLanguage,
    ProgramNode,
    IRNode,
    IRNodeType,
    SourceLocation,
    Scope,
    Symbol,
    SymbolKind,
    ScopeKind,
    TypeInfo,
    Modifier,
    FunctionNode,
    ClassNode,
    MethodNode,
    VariableDeclarationNode,
    CallExpressionNode,
    IdentifierNode,
    StringLiteralNode,
    BlockNode,
    ParameterNode,
    ImportNode,
    MemberExpressionNode
} from '../types';

export abstract class BaseParser {
    protected language: SupportedLanguage;
    protected filePath: string = '';
    protected source: string = '';
    protected scopeStack: Scope[] = [];
    protected currentScopeId: number = 0;

    constructor(language: SupportedLanguage) {
        this.language = language;
    }

    /**
     * Parse source code into a ProgramNode (IR)
     */
    abstract parse(source: string, filePath: string): Promise<ProgramNode>;

    /**
     * Build symbol table from parsed program
     */
    buildSymbolTable(program: ProgramNode): Scope {
        const globalScope = this.createScope('global');
        this.scopeStack = [globalScope];

        this.processImports(program.imports, globalScope);
        this.processNodes(program.body, globalScope);

        return globalScope;
    }

    /**
     * Get supported file extensions for this parser
     */
    abstract getSupportedExtensions(): string[];

    // ========================================================================
    // Scope Management
    // ========================================================================

    protected createScope(kind: ScopeKind, parent?: Scope): Scope {
        const scope: Scope = {
            id: `scope_${++this.currentScopeId}`,
            kind,
            parent,
            children: [],
            symbols: new Map()
        };

        if (parent) {
            parent.children.push(scope);
        }

        return scope;
    }

    protected pushScope(kind: ScopeKind): Scope {
        const parent = this.scopeStack[this.scopeStack.length - 1];
        const scope = this.createScope(kind, parent);
        this.scopeStack.push(scope);
        return scope;
    }

    protected popScope(): Scope | undefined {
        return this.scopeStack.pop();
    }

    protected currentScope(): Scope {
        return this.scopeStack[this.scopeStack.length - 1];
    }

    protected addSymbol(
        name: string,
        kind: SymbolKind,
        location: SourceLocation,
        type?: TypeInfo,
        modifiers: Modifier[] = []
    ): Symbol {
        const symbol: Symbol = {
            name,
            kind,
            type,
            scope: this.currentScope(),
            declaration: location,
            references: [],
            modifiers
        };

        this.currentScope().symbols.set(name, symbol);
        return symbol;
    }

    protected lookupSymbol(name: string): Symbol | undefined {
        for (let i = this.scopeStack.length - 1; i >= 0; i--) {
            const symbol = this.scopeStack[i].symbols.get(name);
            if (symbol) {
                return symbol;
            }
        }
        return undefined;
    }

    // ========================================================================
    // Node Processing for Symbol Table
    // ========================================================================

    protected processNodes(nodes: IRNode[], scope: Scope): void {
        for (const node of nodes) {
            this.processNode(node);
        }
    }

    protected processNode(node: IRNode): void {
        switch (node.type) {
            case 'Function':
                this.processFunctionNode(node as FunctionNode);
                break;
            case 'Class':
                this.processClassNode(node as ClassNode);
                break;
            case 'VariableDeclaration':
                this.processVariableDeclaration(node as VariableDeclarationNode);
                break;
            case 'Block':
                this.processBlockNode(node as BlockNode);
                break;
            default:
                // Process children if any
                if (node.children) {
                    this.processNodes(node.children, this.currentScope());
                }
                break;
        }
    }

    protected processFunctionNode(node: FunctionNode): void {
        // Add function to current scope
        this.addSymbol(
            node.name,
            'function',
            node.location,
            node.returnType,
            node.modifiers
        );

        // Create new scope for function body
        const funcScope = this.pushScope('function');

        // Add parameters to function scope
        for (const param of node.parameters) {
            this.addSymbol(
                param.name,
                'parameter',
                param.location,
                param.paramType
            );
        }

        // Process function body
        if (node.body) {
            this.processNodes(node.body.statements, funcScope);
        }

        this.popScope();
    }

    protected processClassNode(node: ClassNode): void {
        // Add class to current scope
        this.addSymbol(
            node.name,
            'class',
            node.location,
            undefined,
            node.modifiers
        );

        // Create new scope for class body
        const classScope = this.pushScope('class');

        // Process class members
        for (const member of node.members) {
            if (member.type === 'Method') {
                this.processMethodNode(member as MethodNode);
            } else if (member.type === 'Property') {
                this.addSymbol(
                    (member as any).name,
                    'property',
                    member.location,
                    (member as any).valueType,
                    (member as any).modifiers
                );
            }
        }

        this.popScope();
    }

    protected processMethodNode(node: MethodNode): void {
        this.addSymbol(
            node.name,
            'method',
            node.location,
            node.returnType,
            node.modifiers
        );

        if (node.body) {
            const methodScope = this.pushScope('function');

            for (const param of node.parameters) {
                this.addSymbol(
                    param.name,
                    'parameter',
                    param.location,
                    param.paramType
                );
            }

            this.processNodes(node.body.statements, methodScope);
            this.popScope();
        }
    }

    protected processVariableDeclaration(node: VariableDeclarationNode): void {
        this.addSymbol(
            node.name,
            'variable',
            node.location,
            node.varType
        );
    }

    protected processBlockNode(node: BlockNode): void {
        const blockScope = this.pushScope('block');
        this.processNodes(node.statements, blockScope);
        this.popScope();
    }

    protected processImports(imports: ImportNode[], scope: Scope): void {
        for (const imp of imports) {
            for (const spec of imp.specifiers) {
                scope.symbols.set(spec.local, {
                    name: spec.local,
                    kind: 'module',
                    scope,
                    declaration: imp.location,
                    references: [],
                    modifiers: []
                });
            }
        }
    }

    // ========================================================================
    // Helper Methods for Creating IR Nodes
    // ========================================================================

    protected createLocation(
        startLine: number,
        startColumn: number,
        endLine: number,
        endColumn: number
    ): SourceLocation {
        return {
            file: this.filePath,
            startLine,
            startColumn,
            endLine,
            endColumn
        };
    }

    protected createIdentifier(name: string, location: SourceLocation): IdentifierNode {
        return {
            type: 'Identifier',
            name,
            location
        };
    }

    protected createStringLiteral(value: string, raw: string, location: SourceLocation): StringLiteralNode {
        return {
            type: 'StringLiteral',
            value,
            raw,
            location
        };
    }

    protected createCallExpression(
        callee: IRNode,
        args: IRNode[],
        location: SourceLocation
    ): CallExpressionNode {
        return {
            type: 'CallExpression',
            callee,
            arguments: args,
            location
        };
    }

    protected createMemberExpression(
        object: IRNode,
        property: IRNode,
        computed: boolean,
        location: SourceLocation
    ): MemberExpressionNode {
        return {
            type: 'MemberExpression',
            object,
            property,
            computed,
            location
        };
    }

    protected createParameter(
        name: string,
        type: TypeInfo | undefined,
        location: SourceLocation
    ): ParameterNode {
        return {
            type: 'Parameter',
            name,
            paramType: type,
            location
        };
    }

    protected createBlock(statements: IRNode[], location: SourceLocation): BlockNode {
        return {
            type: 'Block',
            statements,
            location
        };
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    protected extractLineContent(source: string, line: number): string {
        const lines = source.split('\n');
        return lines[line - 1] || '';
    }

    public getLanguageId(): SupportedLanguage {
        return this.language;
    }
}

/**
 * Parser Registry - Manages language-specific parsers
 */
export class ParserRegistry {
    private parsers: Map<SupportedLanguage, BaseParser> = new Map();
    private extensionMap: Map<string, SupportedLanguage> = new Map();

    register(parser: BaseParser): void {
        const language = parser.getLanguageId();
        this.parsers.set(language, parser);

        for (const ext of parser.getSupportedExtensions()) {
            this.extensionMap.set(ext.toLowerCase(), language);
        }
    }

    getParser(language: SupportedLanguage): BaseParser | undefined {
        return this.parsers.get(language);
    }

    getParserForFile(filePath: string): BaseParser | undefined {
        const ext = this.getFileExtension(filePath);
        const language = this.extensionMap.get(ext.toLowerCase());
        return language ? this.parsers.get(language) : undefined;
    }

    getLanguageForFile(filePath: string): SupportedLanguage | undefined {
        const ext = this.getFileExtension(filePath);
        return this.extensionMap.get(ext.toLowerCase());
    }

    private getFileExtension(filePath: string): string {
        const parts = filePath.split('.');
        return parts.length > 1 ? `.${parts[parts.length - 1]}` : '';
    }

    getSupportedLanguages(): SupportedLanguage[] {
        return Array.from(this.parsers.keys());
    }
}
