"use strict";
/**
 * Base Parser - Abstract interface for language-specific parsers
 *
 * Provides a unified interface for parsing source code into the IR format.
 * Language-specific parsers extend this class.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParserRegistry = exports.BaseParser = void 0;
class BaseParser {
    constructor(language) {
        this.filePath = '';
        this.source = '';
        this.scopeStack = [];
        this.currentScopeId = 0;
        this.language = language;
    }
    /**
     * Build symbol table from parsed program
     */
    buildSymbolTable(program) {
        const globalScope = this.createScope('global');
        this.scopeStack = [globalScope];
        this.processImports(program.imports, globalScope);
        this.processNodes(program.body, globalScope);
        return globalScope;
    }
    // ========================================================================
    // Scope Management
    // ========================================================================
    createScope(kind, parent) {
        const scope = {
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
    pushScope(kind) {
        const parent = this.scopeStack[this.scopeStack.length - 1];
        const scope = this.createScope(kind, parent);
        this.scopeStack.push(scope);
        return scope;
    }
    popScope() {
        return this.scopeStack.pop();
    }
    currentScope() {
        return this.scopeStack[this.scopeStack.length - 1];
    }
    addSymbol(name, kind, location, type, modifiers = []) {
        const symbol = {
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
    lookupSymbol(name) {
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
    processNodes(nodes, scope) {
        for (const node of nodes) {
            this.processNode(node);
        }
    }
    processNode(node) {
        switch (node.type) {
            case 'Function':
                this.processFunctionNode(node);
                break;
            case 'Class':
                this.processClassNode(node);
                break;
            case 'VariableDeclaration':
                this.processVariableDeclaration(node);
                break;
            case 'Block':
                this.processBlockNode(node);
                break;
            default:
                // Process children if any
                if (node.children) {
                    this.processNodes(node.children, this.currentScope());
                }
                break;
        }
    }
    processFunctionNode(node) {
        // Add function to current scope
        this.addSymbol(node.name, 'function', node.location, node.returnType, node.modifiers);
        // Create new scope for function body
        const funcScope = this.pushScope('function');
        // Add parameters to function scope
        for (const param of node.parameters) {
            this.addSymbol(param.name, 'parameter', param.location, param.paramType);
        }
        // Process function body
        if (node.body) {
            this.processNodes(node.body.statements, funcScope);
        }
        this.popScope();
    }
    processClassNode(node) {
        // Add class to current scope
        this.addSymbol(node.name, 'class', node.location, undefined, node.modifiers);
        // Create new scope for class body
        const classScope = this.pushScope('class');
        // Process class members
        for (const member of node.members) {
            if (member.type === 'Method') {
                this.processMethodNode(member);
            }
            else if (member.type === 'Property') {
                this.addSymbol(member.name, 'property', member.location, member.valueType, member.modifiers);
            }
        }
        this.popScope();
    }
    processMethodNode(node) {
        this.addSymbol(node.name, 'method', node.location, node.returnType, node.modifiers);
        if (node.body) {
            const methodScope = this.pushScope('function');
            for (const param of node.parameters) {
                this.addSymbol(param.name, 'parameter', param.location, param.paramType);
            }
            this.processNodes(node.body.statements, methodScope);
            this.popScope();
        }
    }
    processVariableDeclaration(node) {
        this.addSymbol(node.name, 'variable', node.location, node.varType);
    }
    processBlockNode(node) {
        const blockScope = this.pushScope('block');
        this.processNodes(node.statements, blockScope);
        this.popScope();
    }
    processImports(imports, scope) {
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
    createLocation(startLine, startColumn, endLine, endColumn) {
        return {
            file: this.filePath,
            startLine,
            startColumn,
            endLine,
            endColumn
        };
    }
    createIdentifier(name, location) {
        return {
            type: 'Identifier',
            name,
            location
        };
    }
    createStringLiteral(value, raw, location) {
        return {
            type: 'StringLiteral',
            value,
            raw,
            location
        };
    }
    createCallExpression(callee, args, location) {
        return {
            type: 'CallExpression',
            callee,
            arguments: args,
            location
        };
    }
    createMemberExpression(object, property, computed, location) {
        return {
            type: 'MemberExpression',
            object,
            property,
            computed,
            location
        };
    }
    createParameter(name, type, location) {
        return {
            type: 'Parameter',
            name,
            paramType: type,
            location
        };
    }
    createBlock(statements, location) {
        return {
            type: 'Block',
            statements,
            location
        };
    }
    // ========================================================================
    // Utility Methods
    // ========================================================================
    extractLineContent(source, line) {
        const lines = source.split('\n');
        return lines[line - 1] || '';
    }
    getLanguageId() {
        return this.language;
    }
}
exports.BaseParser = BaseParser;
/**
 * Parser Registry - Manages language-specific parsers
 */
class ParserRegistry {
    constructor() {
        this.parsers = new Map();
        this.extensionMap = new Map();
    }
    register(parser) {
        const language = parser.getLanguageId();
        this.parsers.set(language, parser);
        for (const ext of parser.getSupportedExtensions()) {
            this.extensionMap.set(ext.toLowerCase(), language);
        }
    }
    getParser(language) {
        return this.parsers.get(language);
    }
    getParserForFile(filePath) {
        const ext = this.getFileExtension(filePath);
        const language = this.extensionMap.get(ext.toLowerCase());
        return language ? this.parsers.get(language) : undefined;
    }
    getLanguageForFile(filePath) {
        const ext = this.getFileExtension(filePath);
        return this.extensionMap.get(ext.toLowerCase());
    }
    getFileExtension(filePath) {
        const parts = filePath.split('.');
        return parts.length > 1 ? `.${parts[parts.length - 1]}` : '';
    }
    getSupportedLanguages() {
        return Array.from(this.parsers.keys());
    }
}
exports.ParserRegistry = ParserRegistry;
//# sourceMappingURL=baseParser.js.map