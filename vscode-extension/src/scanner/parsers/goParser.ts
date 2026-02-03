/**
 * Go Parser
 *
 * Parses Go source code into the unified IR format for security analysis.
 * Uses regex-based parsing to extract security-relevant structures.
 */

import { BaseParser } from './baseParser';
import {
    SupportedLanguage,
    ProgramNode,
    IRNode,
    SourceLocation,
    FunctionNode,
    ClassNode,
    MethodNode,
    PropertyNode,
    ParameterNode,
    BlockNode,
    VariableDeclarationNode,
    AssignmentNode,
    IfNode,
    ForNode,
    ForEachNode,
    ReturnNode,
    CallExpressionNode,
    MemberExpressionNode,
    IdentifierNode,
    StringLiteralNode,
    ImportNode,
    ImportSpecifier,
    TypeInfo,
    Modifier
} from '../types';

interface GoStruct {
    name: string;
    fields: PropertyNode[];
    methods: MethodNode[];
    startLine: number;
    endLine: number;
}

export class GoParser extends BaseParser {
    private lines: string[] = [];
    private currentLine: number = 0;
    private structs: Map<string, GoStruct> = new Map();

    constructor() {
        super('go');
    }

    getSupportedExtensions(): string[] {
        return ['.go'];
    }

    async parse(source: string, filePath: string): Promise<ProgramNode> {
        this.source = source;
        this.filePath = filePath;
        this.lines = source.split('\n');
        this.currentLine = 0;
        this.structs.clear();

        const imports: ImportNode[] = [];
        const body: IRNode[] = [];

        while (this.currentLine < this.lines.length) {
            const line = this.lines[this.currentLine];
            const trimmed = line.trim();

            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('//')) {
                this.currentLine++;
                continue;
            }

            // Skip multi-line comments
            if (trimmed.startsWith('/*')) {
                this.skipMultiLineComment();
                continue;
            }

            // Skip package declaration
            if (trimmed.startsWith('package ')) {
                this.currentLine++;
                continue;
            }

            // Parse imports
            if (trimmed.startsWith('import ')) {
                const importNodes = this.parseImports();
                imports.push(...importNodes);
                continue;
            }

            // Parse type declarations (struct, interface)
            if (trimmed.startsWith('type ')) {
                const typeNode = this.parseTypeDeclaration();
                if (typeNode) {
                    body.push(typeNode);
                }
                continue;
            }

            // Parse function declarations
            if (trimmed.startsWith('func ')) {
                const funcNode = this.parseFunction();
                if (funcNode) {
                    body.push(funcNode);
                }
                continue;
            }

            // Parse var declarations
            if (trimmed.startsWith('var ')) {
                const varNode = this.parseVarDeclaration();
                if (varNode) {
                    body.push(varNode);
                }
                continue;
            }

            // Parse const declarations
            if (trimmed.startsWith('const ')) {
                const constNode = this.parseConstDeclaration();
                if (constNode) {
                    body.push(constNode);
                }
                continue;
            }

            this.currentLine++;
        }

        // Convert structs to classes
        for (const struct of this.structs.values()) {
            const classNode: ClassNode = {
                type: 'Class',
                name: struct.name,
                modifiers: this.getExportModifiers(struct.name),
                members: [...struct.fields, ...struct.methods],
                location: this.createLocation(struct.startLine + 1, 0, struct.endLine + 1, 0)
            };
            body.push(classNode);
        }

        return {
            type: 'Program',
            language: 'go',
            imports,
            body,
            exports: [],
            location: this.createLocation(1, 0, this.lines.length, this.lines[this.lines.length - 1]?.length || 0)
        };
    }

    private skipMultiLineComment(): void {
        while (this.currentLine < this.lines.length) {
            if (this.lines[this.currentLine].includes('*/')) {
                this.currentLine++;
                break;
            }
            this.currentLine++;
        }
    }

    private parseImports(): ImportNode[] {
        const imports: ImportNode[] = [];
        const line = this.lines[this.currentLine].trim();

        // Single import
        if (line.match(/^import\s+"[\w/.]+"/)) {
            const match = line.match(/^import\s+(?:(\w+)\s+)?"([\w/.]+)"/);
            if (match) {
                const alias = match[1];
                const source = match[2];
                imports.push({
                    type: 'Import',
                    source,
                    specifiers: [{
                        local: alias || source.split('/').pop() || source,
                        imported: source
                    }],
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
                });
            }
            this.currentLine++;
            return imports;
        }

        // Multi-line import block
        if (line.startsWith('import (')) {
            this.currentLine++;
            while (this.currentLine < this.lines.length) {
                const importLine = this.lines[this.currentLine].trim();

                if (importLine === ')') {
                    this.currentLine++;
                    break;
                }

                if (!importLine || importLine.startsWith('//')) {
                    this.currentLine++;
                    continue;
                }

                const match = importLine.match(/^(?:(\w+)\s+)?"([\w/.]+)"/);
                if (match) {
                    const alias = match[1];
                    const source = match[2];
                    imports.push({
                        type: 'Import',
                        source,
                        specifiers: [{
                            local: alias || source.split('/').pop() || source,
                            imported: source
                        }],
                        location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, importLine.length)
                    });
                }

                this.currentLine++;
            }
            return imports;
        }

        this.currentLine++;
        return imports;
    }

    private parseTypeDeclaration(): ClassNode | null {
        const startLine = this.currentLine;
        let header = this.lines[this.currentLine].trim();

        // Handle multi-line type declaration
        while (!header.includes('{') && !header.includes('interface') && this.currentLine < this.lines.length - 1) {
            this.currentLine++;
            header += ' ' + this.lines[this.currentLine].trim();
        }

        // Struct definition
        const structMatch = header.match(/^type\s+(\w+)\s+struct\s*\{?/);
        if (structMatch) {
            const name = structMatch[1];
            const fields: PropertyNode[] = [];

            // Find opening brace if not on same line
            if (!header.includes('{')) {
                this.currentLine++;
                while (this.currentLine < this.lines.length && !this.lines[this.currentLine].includes('{')) {
                    this.currentLine++;
                }
            }

            this.currentLine++;

            // Parse struct fields
            while (this.currentLine < this.lines.length) {
                const fieldLine = this.lines[this.currentLine].trim();

                if (fieldLine === '}') {
                    break;
                }

                if (!fieldLine || fieldLine.startsWith('//')) {
                    this.currentLine++;
                    continue;
                }

                const field = this.parseStructField(fieldLine);
                if (field) {
                    fields.push(field);
                }

                this.currentLine++;
            }

            this.currentLine++;

            // Store struct for method association
            this.structs.set(name, {
                name,
                fields,
                methods: [],
                startLine,
                endLine: this.currentLine
            });

            return {
                type: 'Class',
                name,
                modifiers: this.getExportModifiers(name),
                members: fields,
                location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
            };
        }

        // Interface definition
        const interfaceMatch = header.match(/^type\s+(\w+)\s+interface\s*\{?/);
        if (interfaceMatch) {
            const name = interfaceMatch[1];
            const methods: MethodNode[] = [];

            // Find opening brace
            if (!header.includes('{')) {
                this.currentLine++;
            }

            this.currentLine++;

            // Parse interface methods
            while (this.currentLine < this.lines.length) {
                const methodLine = this.lines[this.currentLine].trim();

                if (methodLine === '}') {
                    break;
                }

                if (!methodLine || methodLine.startsWith('//')) {
                    this.currentLine++;
                    continue;
                }

                const method = this.parseInterfaceMethod(methodLine);
                if (method) {
                    methods.push(method);
                }

                this.currentLine++;
            }

            this.currentLine++;

            return {
                type: 'Class',
                name,
                modifiers: this.getExportModifiers(name),
                members: methods,
                isAbstract: true, // Interfaces are abstract
                location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
            };
        }

        // Type alias
        const aliasMatch = header.match(/^type\s+(\w+)\s+(\S+)/);
        if (aliasMatch) {
            this.currentLine++;
            return null; // Skip type aliases for now
        }

        this.currentLine++;
        return null;
    }

    private parseStructField(line: string): PropertyNode | null {
        // Handle embedded field: FieldType
        // Handle named field: FieldName FieldType `json:"tag"`

        // Remove tags
        const withoutTag = line.replace(/`[^`]+`/, '').trim();

        // Named field
        const namedMatch = withoutTag.match(/^(\w+)\s+([\w*\[\].<>]+)/);
        if (namedMatch) {
            return {
                type: 'Property',
                name: namedMatch[1],
                valueType: { name: namedMatch[2] },
                modifiers: this.getExportModifiers(namedMatch[1]),
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
        }

        // Embedded field
        const embeddedMatch = withoutTag.match(/^\*?(\w+)/);
        if (embeddedMatch) {
            return {
                type: 'Property',
                name: embeddedMatch[1],
                valueType: { name: withoutTag },
                modifiers: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
        }

        return null;
    }

    private parseInterfaceMethod(line: string): MethodNode | null {
        // MethodName(params) (returns)
        const match = line.match(/^(\w+)\s*\(([^)]*)\)\s*(?:\(([^)]*)\)|(\S+))?/);
        if (!match) return null;

        const name = match[1];
        const paramsStr = match[2];
        const returnsMulti = match[3];
        const returnsSingle = match[4];

        const parameters = this.parseParameters(paramsStr);
        const returnType = returnsMulti || returnsSingle
            ? { name: returnsMulti || returnsSingle }
            : undefined;

        return {
            type: 'Method',
            name,
            parameters,
            returnType,
            modifiers: this.getExportModifiers(name),
            isAbstract: true,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }

    private parseFunction(): FunctionNode | MethodNode | null {
        const startLine = this.currentLine;
        let header = '';

        // Collect function header
        while (this.currentLine < this.lines.length && !header.includes('{')) {
            header += ' ' + this.lines[this.currentLine].trim();
            this.currentLine++;
        }

        // Method with receiver: func (r *Receiver) MethodName(params) (returns)
        const methodMatch = header.match(
            /func\s*\(\s*(\w+)\s+(\*?\w+)\s*\)\s*(\w+)\s*\(([^)]*)\)\s*(?:\(([^)]*)\)|(\S+))?/
        );

        if (methodMatch) {
            const receiverName = methodMatch[1];
            const receiverType = methodMatch[2].replace('*', '');
            const name = methodMatch[3];
            const paramsStr = methodMatch[4];
            const returnsMulti = methodMatch[5];
            const returnsSingle = methodMatch[6];

            const parameters = this.parseParameters(paramsStr);
            const returnType = returnsMulti || returnsSingle
                ? { name: returnsMulti || returnsSingle }
                : undefined;

            const body = this.parseFunctionBody();

            const method: MethodNode = {
                type: 'Method',
                name,
                parameters,
                returnType,
                body,
                modifiers: this.getExportModifiers(name),
                location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
            };

            // Associate method with struct
            const struct = this.structs.get(receiverType);
            if (struct) {
                struct.methods.push(method);
            }

            return method;
        }

        // Regular function: func FuncName(params) (returns)
        const funcMatch = header.match(
            /func\s+(\w+)\s*\(([^)]*)\)\s*(?:\(([^)]*)\)|(\S+))?/
        );

        if (funcMatch) {
            const name = funcMatch[1];
            const paramsStr = funcMatch[2];
            const returnsMulti = funcMatch[3];
            const returnsSingle = funcMatch[4];

            const parameters = this.parseParameters(paramsStr);
            const returnType = returnsMulti || returnsSingle
                ? { name: returnsMulti || returnsSingle }
                : undefined;

            const body = this.parseFunctionBody();

            return {
                type: 'Function',
                name,
                parameters,
                returnType,
                body,
                modifiers: this.getExportModifiers(name),
                location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
            };
        }

        return null;
    }

    private parseParameters(paramsStr: string): ParameterNode[] {
        const parameters: ParameterNode[] = [];

        if (!paramsStr.trim()) {
            return parameters;
        }

        // Split by comma, handling nested types
        const params = this.splitByComma(paramsStr);

        // Go can have multiple params with same type: a, b int
        let pendingNames: string[] = [];

        for (const param of params) {
            const trimmed = param.trim();
            if (!trimmed) continue;

            // Check if this is "name type" or just "name"
            const parts = trimmed.split(/\s+/);

            if (parts.length === 1) {
                // Could be just a name waiting for type
                pendingNames.push(parts[0]);
            } else {
                // Last part is the type
                const typeStr = parts[parts.length - 1];
                const names = [...pendingNames, ...parts.slice(0, -1)];
                pendingNames = [];

                for (const name of names) {
                    if (name.startsWith('...')) {
                        parameters.push({
                            type: 'Parameter',
                            name: name.substring(3),
                            paramType: { name: typeStr },
                            isRest: true,
                            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
                        });
                    } else {
                        parameters.push({
                            type: 'Parameter',
                            name,
                            paramType: { name: typeStr },
                            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
                        });
                    }
                }
            }
        }

        return parameters;
    }

    private parseFunctionBody(): BlockNode {
        const statements: IRNode[] = [];
        const startLine = this.currentLine;
        let braceCount = 1;

        while (this.currentLine < this.lines.length && braceCount > 0) {
            const line = this.lines[this.currentLine];
            const trimmed = line.trim();

            // Track brace count
            for (const char of line) {
                if (char === '{') braceCount++;
                else if (char === '}') braceCount--;
            }

            if (braceCount === 0) {
                break;
            }

            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('//')) {
                this.currentLine++;
                continue;
            }

            // Parse statements
            const stmt = this.parseStatement(trimmed);
            if (stmt) {
                statements.push(stmt);
            }

            this.currentLine++;
        }

        this.currentLine++;

        return {
            type: 'Block',
            statements,
            location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
        };
    }

    private parseStatement(trimmed: string): IRNode | null {
        // Return statement
        if (trimmed.startsWith('return ') || trimmed === 'return') {
            return this.parseReturn(trimmed);
        }

        // If statement
        if (trimmed.startsWith('if ')) {
            return this.parseIf(trimmed);
        }

        // For loop (Go only has for, no while)
        if (trimmed.startsWith('for ')) {
            return this.parseFor(trimmed);
        }

        // Short variable declaration (:=)
        if (trimmed.includes(':=')) {
            return this.parseShortVarDecl(trimmed);
        }

        // Assignment
        if (trimmed.includes('=') && !trimmed.includes('==') && !trimmed.includes(':=')) {
            return this.parseAssignment(trimmed);
        }

        // Defer/go statement
        if (trimmed.startsWith('defer ') || trimmed.startsWith('go ')) {
            return this.parseExpression(trimmed.substring(trimmed.indexOf(' ') + 1));
        }

        // Expression statement
        return this.parseExpression(trimmed);
    }

    private parseReturn(line: string): ReturnNode {
        const match = line.match(/^return\s*(.*)$/);
        const argumentStr = match?.[1];

        let argument: IRNode | undefined;
        if (argumentStr) {
            argument = this.parseExpression(argumentStr);
        }

        return {
            type: 'Return',
            argument,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }

    private parseIf(line: string): IfNode | null {
        // Go if can have initialization: if err := foo(); err != nil
        const match = line.match(/^if\s+(?:(\w+)\s*:=\s*(.+?);\s*)?(.+?)\s*\{?$/);
        if (!match) return null;

        const conditionStr = match[3];
        const condition = this.parseExpression(conditionStr) || {
            type: 'Identifier',
            name: 'condition',
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        } as IdentifierNode;

        return {
            type: 'If',
            condition,
            thenBranch: {
                type: 'Block',
                statements: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
            },
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }

    private parseFor(line: string): ForNode | ForEachNode | null {
        // Range-based for: for key, value := range collection
        const rangeMatch = line.match(/^for\s+(?:(\w+)(?:\s*,\s*(\w+))?\s*:=\s*)?range\s+(.+?)\s*\{?$/);
        if (rangeMatch) {
            const keyName = rangeMatch[1] || '_';
            const valueName = rangeMatch[2];
            const collectionStr = rangeMatch[3];

            const variable: VariableDeclarationNode = {
                type: 'VariableDeclaration',
                name: valueName || keyName,
                kind: 'var',
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };

            const iterable = this.parseExpression(collectionStr) || {
                type: 'Identifier',
                name: collectionStr,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            } as IdentifierNode;

            return {
                type: 'ForEach',
                variable,
                iterable,
                body: {
                    type: 'Block',
                    statements: [],
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
                },
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
        }

        // Traditional for: for init; condition; post
        const forMatch = line.match(/^for\s+(?:(.+?);\s*(.+?);\s*(.+?))?\s*\{?$/);
        if (forMatch && forMatch[1]) {
            return {
                type: 'For',
                init: this.parseExpression(forMatch[1]) || undefined,
                test: this.parseExpression(forMatch[2]) || undefined,
                update: this.parseExpression(forMatch[3]) || undefined,
                body: {
                    type: 'Block',
                    statements: [],
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
                },
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
        }

        // While-style for: for condition
        const whileMatch = line.match(/^for\s+(.+?)\s*\{?$/);
        if (whileMatch) {
            return {
                type: 'For',
                test: this.parseExpression(whileMatch[1]) || undefined,
                body: {
                    type: 'Block',
                    statements: [],
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
                },
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
        }

        // Infinite loop: for {
        return {
            type: 'For',
            body: {
                type: 'Block',
                statements: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
            },
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }

    private parseShortVarDecl(line: string): VariableDeclarationNode | null {
        const match = line.match(/^([\w,\s]+)\s*:=\s*(.+)$/);
        if (!match) return null;

        const names = match[1].split(',').map(n => n.trim());
        const valueStr = match[2];

        const initializer = this.parseExpression(valueStr);

        return {
            type: 'VariableDeclaration',
            name: names[0], // Use first name
            initializer: initializer || undefined,
            kind: 'var',
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }

    private parseAssignment(line: string): AssignmentNode | null {
        const match = line.match(/^([\w.\[\]]+)\s*([+\-*/&|^%]?=)\s*(.+)$/);
        if (!match) return null;

        const leftStr = match[1];
        const operator = match[2];
        const rightStr = match[3];

        const left = this.parseExpression(leftStr) || {
            type: 'Identifier',
            name: leftStr,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, leftStr.length)
        } as IdentifierNode;

        const right = this.parseExpression(rightStr) || {
            type: 'Identifier',
            name: rightStr,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, rightStr.length)
        } as IdentifierNode;

        return {
            type: 'Assignment',
            left,
            right,
            operator,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }

    private parseVarDeclaration(): VariableDeclarationNode | null {
        const line = this.lines[this.currentLine].trim();

        // var name type = value
        const match = line.match(/^var\s+(\w+)\s+([\w*\[\].<>]+)?\s*(?:=\s*(.+))?$/);
        if (match) {
            const name = match[1];
            const typeStr = match[2];
            const valueStr = match[3];

            this.currentLine++;

            return {
                type: 'VariableDeclaration',
                name,
                varType: typeStr ? { name: typeStr } : undefined,
                initializer: valueStr ? this.parseExpression(valueStr) || undefined : undefined,
                kind: 'var',
                location: this.createLocation(this.currentLine, 0, this.currentLine, line.length)
            };
        }

        // var ( block )
        if (line === 'var (') {
            this.currentLine++;
            // Skip var block for now
            while (this.currentLine < this.lines.length && this.lines[this.currentLine].trim() !== ')') {
                this.currentLine++;
            }
            this.currentLine++;
        } else {
            this.currentLine++;
        }

        return null;
    }

    private parseConstDeclaration(): VariableDeclarationNode | null {
        const line = this.lines[this.currentLine].trim();

        // const name = value
        const match = line.match(/^const\s+(\w+)(?:\s+([\w*\[\].<>]+))?\s*=\s*(.+)$/);
        if (match) {
            const name = match[1];
            const typeStr = match[2];
            const valueStr = match[3];

            this.currentLine++;

            return {
                type: 'VariableDeclaration',
                name,
                varType: typeStr ? { name: typeStr } : undefined,
                initializer: this.parseExpression(valueStr) || undefined,
                kind: 'const',
                location: this.createLocation(this.currentLine, 0, this.currentLine, line.length)
            };
        }

        // const ( block )
        if (line === 'const (') {
            this.currentLine++;
            while (this.currentLine < this.lines.length && this.lines[this.currentLine].trim() !== ')') {
                this.currentLine++;
            }
            this.currentLine++;
        } else {
            this.currentLine++;
        }

        return null;
    }

    private parseExpression(expr: string): IRNode | null {
        const trimmed = expr.trim();

        if (!trimmed) return null;

        // String literal
        if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
            (trimmed.startsWith('`') && trimmed.endsWith('`'))) {
            return {
                type: 'StringLiteral',
                value: trimmed.slice(1, -1),
                raw: trimmed,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            };
        }

        // Number literal
        if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
            return {
                type: 'NumberLiteral',
                value: parseFloat(trimmed),
                raw: trimmed,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            };
        }

        // Boolean literals
        if (trimmed === 'true' || trimmed === 'false') {
            return {
                type: 'BooleanLiteral',
                value: trimmed === 'true',
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            } as IRNode;
        }

        // Nil literal
        if (trimmed === 'nil') {
            return {
                type: 'NullLiteral',
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            } as IRNode;
        }

        // Function call
        const callMatch = trimmed.match(/^([\w.]+)\s*\((.*)\)$/s);
        if (callMatch) {
            return this.parseCallExpression(callMatch[1], callMatch[2]);
        }

        // Composite literal: Type{...}
        const compositMatch = trimmed.match(/^([\w.*]+)\s*\{/);
        if (compositMatch) {
            return {
                type: 'NewExpression',
                callee: {
                    type: 'Identifier',
                    name: compositMatch[1],
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, compositMatch[1].length)
                },
                arguments: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            };
        }

        // Member expression
        if (trimmed.includes('.') && !trimmed.includes('(')) {
            return this.parseMemberExpression(trimmed);
        }

        // Simple identifier
        if (/^[\w]+$/.test(trimmed)) {
            return {
                type: 'Identifier',
                name: trimmed,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            };
        }

        // Default
        return {
            type: 'Identifier',
            name: trimmed,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
        };
    }

    private parseCallExpression(calleeStr: string, argsStr: string): CallExpressionNode {
        let callee: IRNode;

        if (calleeStr.includes('.')) {
            callee = this.parseMemberExpression(calleeStr)!;
        } else {
            callee = {
                type: 'Identifier',
                name: calleeStr,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, calleeStr.length)
            };
        }

        const args: IRNode[] = [];
        if (argsStr.trim()) {
            const argsList = this.splitByComma(argsStr);
            for (const arg of argsList) {
                const parsed = this.parseExpression(arg.trim());
                if (parsed) args.push(parsed);
            }
        }

        return {
            type: 'CallExpression',
            callee,
            arguments: args,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, calleeStr.length + argsStr.length + 2)
        };
    }

    private parseMemberExpression(expr: string): MemberExpressionNode | null {
        const parts = expr.split('.');
        if (parts.length < 2) return null;

        let current: IRNode = {
            type: 'Identifier',
            name: parts[0],
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, parts[0].length)
        };

        for (let i = 1; i < parts.length; i++) {
            current = {
                type: 'MemberExpression',
                object: current,
                property: {
                    type: 'Identifier',
                    name: parts[i],
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, parts[i].length)
                },
                computed: false,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
            };
        }

        return current as MemberExpressionNode;
    }

    private getExportModifiers(name: string): Modifier[] {
        // In Go, exported names start with uppercase
        if (name && name[0] === name[0].toUpperCase() && name[0] !== name[0].toLowerCase()) {
            return ['public'];
        }
        return ['private'];
    }

    private splitByComma(str: string): string[] {
        const result: string[] = [];
        let current = '';
        let depth = 0;

        for (const char of str) {
            if (char === '<' || char === '(' || char === '[' || char === '{') {
                depth++;
            } else if (char === '>' || char === ')' || char === ']' || char === '}') {
                depth--;
            } else if (char === ',' && depth === 0) {
                result.push(current);
                current = '';
                continue;
            }
            current += char;
        }

        if (current.trim()) {
            result.push(current);
        }

        return result;
    }
}

export function createGoParser(): GoParser {
    return new GoParser();
}
