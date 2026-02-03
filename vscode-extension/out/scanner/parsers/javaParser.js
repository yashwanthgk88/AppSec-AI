"use strict";
/**
 * Java Parser
 *
 * Parses Java source code into the unified IR format for security analysis.
 * Uses regex-based parsing to extract security-relevant structures.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.JavaParser = void 0;
exports.createJavaParser = createJavaParser;
const baseParser_1 = require("./baseParser");
class JavaParser extends baseParser_1.BaseParser {
    constructor() {
        super('java');
        this.lines = [];
        this.currentLine = 0;
    }
    getSupportedExtensions() {
        return ['.java'];
    }
    async parse(source, filePath) {
        this.source = source;
        this.filePath = filePath;
        this.lines = source.split('\n');
        this.currentLine = 0;
        const imports = [];
        const body = [];
        while (this.currentLine < this.lines.length) {
            const line = this.lines[this.currentLine];
            const trimmed = line.trim();
            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
                // Handle multi-line comments
                if (trimmed.startsWith('/*')) {
                    this.skipMultiLineComment();
                    continue;
                }
                this.currentLine++;
                continue;
            }
            // Skip package declaration
            if (trimmed.startsWith('package ')) {
                this.currentLine++;
                continue;
            }
            // Parse imports
            if (trimmed.startsWith('import ')) {
                const importNode = this.parseImport(line);
                if (importNode) {
                    imports.push(importNode);
                }
                this.currentLine++;
                continue;
            }
            // Parse class/interface/enum declarations
            if (this.isClassDeclaration(trimmed)) {
                const classNode = this.parseClass();
                if (classNode) {
                    body.push(classNode);
                }
                continue;
            }
            // Parse annotations
            if (trimmed.startsWith('@')) {
                this.currentLine++;
                continue;
            }
            this.currentLine++;
        }
        return {
            type: 'Program',
            language: 'java',
            imports,
            body,
            exports: [],
            location: this.createLocation(1, 0, this.lines.length, this.lines[this.lines.length - 1]?.length || 0)
        };
    }
    skipMultiLineComment() {
        while (this.currentLine < this.lines.length) {
            if (this.lines[this.currentLine].includes('*/')) {
                this.currentLine++;
                break;
            }
            this.currentLine++;
        }
    }
    parseImport(line) {
        const trimmed = line.trim();
        const match = trimmed.match(/^import\s+(static\s+)?([\w.*]+);?$/);
        if (!match) {
            return null;
        }
        const isStatic = !!match[1];
        const source = match[2];
        const isWildcard = source.endsWith('.*');
        const parts = source.split('.');
        const local = isWildcard ? '*' : parts[parts.length - 1];
        return {
            type: 'Import',
            source: source.replace('.*', ''),
            specifiers: [{
                    local,
                    imported: local
                }],
            isNamespace: isWildcard,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }
    isClassDeclaration(line) {
        return /(?:public|private|protected|abstract|final|static)?\s*(?:class|interface|enum|record)\s+\w+/.test(line);
    }
    parseClass() {
        const startLine = this.currentLine;
        let headerLine = '';
        // Collect multi-line class declaration
        while (this.currentLine < this.lines.length && !headerLine.includes('{')) {
            headerLine += ' ' + this.lines[this.currentLine].trim();
            this.currentLine++;
        }
        const classMatch = headerLine.match(/(?:(public|private|protected|abstract|final|static)\s+)*(?:(class|interface|enum|record))\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+([\w.]+))?(?:\s+implements\s+([\w.,\s]+))?/);
        if (!classMatch) {
            return null;
        }
        const modifiers = this.extractModifiers(headerLine);
        const classType = classMatch[2];
        const name = classMatch[3];
        const superClass = classMatch[4];
        const interfacesStr = classMatch[5];
        const interfaces = interfacesStr
            ? interfacesStr.split(',').map(i => i.trim())
            : [];
        const members = [];
        // Find the opening brace
        let braceCount = 1;
        const braceIndex = headerLine.indexOf('{');
        if (braceIndex === -1) {
            return null;
        }
        // Parse class body
        while (this.currentLine < this.lines.length && braceCount > 0) {
            const line = this.lines[this.currentLine];
            const trimmed = line.trim();
            // Track brace count
            for (const char of line) {
                if (char === '{')
                    braceCount++;
                else if (char === '}')
                    braceCount--;
            }
            if (braceCount === 0) {
                break;
            }
            // Skip empty lines, comments, and annotations
            if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') ||
                trimmed.startsWith('*') || trimmed.startsWith('@')) {
                if (trimmed.startsWith('/*')) {
                    this.skipMultiLineComment();
                    continue;
                }
                this.currentLine++;
                continue;
            }
            // Parse nested class
            if (this.isClassDeclaration(trimmed)) {
                const nestedClass = this.parseClass();
                if (nestedClass) {
                    // Could add as nested class if needed
                }
                continue;
            }
            // Parse constructor
            if (this.isConstructor(trimmed, name)) {
                const ctor = this.parseConstructor(name);
                if (ctor) {
                    members.push(ctor);
                }
                continue;
            }
            // Parse method
            if (this.isMethodDeclaration(trimmed)) {
                const method = this.parseMethod();
                if (method) {
                    members.push(method);
                }
                continue;
            }
            // Parse field
            if (this.isFieldDeclaration(trimmed)) {
                const field = this.parseField();
                if (field) {
                    members.push(field);
                }
                continue;
            }
            this.currentLine++;
        }
        this.currentLine++;
        return {
            type: 'Class',
            name,
            superClass,
            interfaces,
            modifiers,
            members,
            isAbstract: modifiers.includes('abstract'),
            location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
        };
    }
    isConstructor(line, className) {
        const pattern = new RegExp(`(?:public|private|protected)?\\s*${className}\\s*\\(`);
        return pattern.test(line) && !line.includes(' new ');
    }
    isMethodDeclaration(line) {
        // Method has a return type, name, and parentheses
        return /(?:public|private|protected|static|final|abstract|synchronized|native)?\s*(?:[\w<>,\[\]\s]+)\s+(\w+)\s*\(/.test(line) &&
            !line.includes(' new ') &&
            !line.includes('=');
    }
    isFieldDeclaration(line) {
        // Field has a type, name, and typically ends with ; or =
        return /(?:public|private|protected|static|final|volatile|transient)?\s*(?:[\w<>,\[\]]+)\s+(\w+)\s*[;=]/.test(line);
    }
    parseConstructor(className) {
        const startLine = this.currentLine;
        let header = '';
        // Collect constructor header
        while (this.currentLine < this.lines.length && !header.includes('{')) {
            header += ' ' + this.lines[this.currentLine].trim();
            this.currentLine++;
        }
        const ctorMatch = header.match(new RegExp(`(public|private|protected)?\\s*${className}\\s*\\(([^)]*)\\)`));
        if (!ctorMatch) {
            return null;
        }
        const modifiers = this.extractModifiers(header);
        const parameters = this.parseParameters(ctorMatch[2] || '');
        const body = this.parseMethodBody();
        return {
            type: 'Constructor',
            parameters,
            body,
            modifiers,
            location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
        };
    }
    parseMethod() {
        const startLine = this.currentLine;
        let header = '';
        // Collect method header
        while (this.currentLine < this.lines.length) {
            const line = this.lines[this.currentLine].trim();
            header += ' ' + line;
            this.currentLine++;
            if (line.includes('{') || line.endsWith(';')) {
                break;
            }
        }
        // Extract method signature
        const methodMatch = header.match(/(?:(public|private|protected|static|final|abstract|synchronized|native)\s+)*(?:(\w+(?:<[^>]+>)?(?:\[\])?)\s+)?(\w+)\s*\(([^)]*)\)/);
        if (!methodMatch) {
            return null;
        }
        const modifiers = this.extractModifiers(header);
        const returnTypeStr = methodMatch[2] || 'void';
        const name = methodMatch[3];
        const paramsStr = methodMatch[4];
        const parameters = this.parseParameters(paramsStr);
        const returnType = { name: returnTypeStr };
        let body;
        // Abstract methods don't have body
        if (!header.endsWith(';')) {
            body = this.parseMethodBody();
        }
        return {
            type: 'Method',
            name,
            parameters,
            returnType,
            body,
            modifiers,
            isAsync: false,
            isStatic: modifiers.includes('static'),
            isAbstract: modifiers.includes('abstract'),
            location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
        };
    }
    parseField() {
        const startLine = this.currentLine;
        let line = this.lines[this.currentLine].trim();
        // Handle multi-line field declarations
        while (!line.includes(';') && this.currentLine < this.lines.length - 1) {
            this.currentLine++;
            line += ' ' + this.lines[this.currentLine].trim();
        }
        const fieldMatch = line.match(/(?:(public|private|protected|static|final|volatile|transient)\s+)*([\w<>,\[\]]+)\s+(\w+)(?:\s*=\s*(.+?))?;/);
        if (!fieldMatch) {
            this.currentLine++;
            return null;
        }
        const modifiers = this.extractModifiers(line);
        const valueType = { name: fieldMatch[2] };
        const name = fieldMatch[3];
        const initializerStr = fieldMatch[4];
        const initializer = initializerStr ? this.parseExpression(initializerStr) : undefined;
        this.currentLine++;
        return {
            type: 'Property',
            name,
            valueType,
            initializer,
            modifiers,
            isStatic: modifiers.includes('static'),
            location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
        };
    }
    parseParameters(paramsStr) {
        const parameters = [];
        if (!paramsStr.trim()) {
            return parameters;
        }
        // Split by comma, handling generics
        const params = this.splitByComma(paramsStr);
        for (const param of params) {
            const trimmed = param.trim();
            if (!trimmed)
                continue;
            // Handle: final Type name, Type... name, Type[] name
            const paramMatch = trimmed.match(/(?:(final)\s+)?([\w<>,\[\]]+(?:\.\.\.)?)\s+(\w+)/);
            if (paramMatch) {
                const isFinal = !!paramMatch[1];
                const typeStr = paramMatch[2];
                const name = paramMatch[3];
                const isRest = typeStr.includes('...');
                const modifiers = [];
                if (isFinal)
                    modifiers.push('final');
                parameters.push({
                    type: 'Parameter',
                    name,
                    paramType: { name: typeStr.replace('...', '[]') },
                    isRest,
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
                });
            }
        }
        return parameters;
    }
    parseMethodBody() {
        const statements = [];
        const startLine = this.currentLine;
        let braceCount = 1;
        while (this.currentLine < this.lines.length && braceCount > 0) {
            const line = this.lines[this.currentLine];
            const trimmed = line.trim();
            // Track brace count
            for (const char of line) {
                if (char === '{')
                    braceCount++;
                else if (char === '}')
                    braceCount--;
            }
            if (braceCount === 0) {
                break;
            }
            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*')) {
                if (trimmed.startsWith('/*')) {
                    this.skipMultiLineComment();
                    continue;
                }
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
    parseStatement(trimmed) {
        // Variable declaration
        if (this.isVariableDeclaration(trimmed)) {
            return this.parseVariableDeclaration(trimmed);
        }
        // Return statement
        if (trimmed.startsWith('return ') || trimmed === 'return;') {
            return this.parseReturn(trimmed);
        }
        // Throw statement
        if (trimmed.startsWith('throw ')) {
            return this.parseThrow(trimmed);
        }
        // If statement
        if (trimmed.startsWith('if ') || trimmed.startsWith('if(')) {
            return this.parseIf(trimmed);
        }
        // For loop
        if (trimmed.startsWith('for ') || trimmed.startsWith('for(')) {
            return this.parseFor(trimmed);
        }
        // While loop
        if (trimmed.startsWith('while ') || trimmed.startsWith('while(')) {
            return this.parseWhile(trimmed);
        }
        // Try-catch
        if (trimmed.startsWith('try ') || trimmed === 'try{' || trimmed === 'try {') {
            return this.parseTry();
        }
        // Assignment
        if (trimmed.includes('=') && !trimmed.includes('==') && !trimmed.includes('!=')) {
            return this.parseAssignment(trimmed);
        }
        // Expression statement (method call, etc.)
        return this.parseExpression(trimmed);
    }
    isVariableDeclaration(line) {
        // Check for type name = value; or type name;
        return /^(?:final\s+)?[\w<>,\[\]]+\s+\w+\s*(?:=|;)/.test(line);
    }
    parseVariableDeclaration(line) {
        const match = line.match(/^(?:(final)\s+)?([\w<>,\[\]]+)\s+(\w+)(?:\s*=\s*(.+?))?;?$/);
        if (!match) {
            return null;
        }
        const isFinal = !!match[1];
        const typeStr = match[2];
        const name = match[3];
        const initializerStr = match[4];
        const initializer = initializerStr ? this.parseExpression(initializerStr) : undefined;
        return {
            type: 'VariableDeclaration',
            name,
            varType: { name: typeStr },
            initializer,
            kind: isFinal ? 'final' : 'var',
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }
    parseReturn(line) {
        const match = line.match(/^return\s*(.+)?;?$/);
        const argumentStr = match?.[1];
        const argument = argumentStr ? this.parseExpression(argumentStr) : undefined;
        return {
            type: 'Return',
            argument,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }
    parseThrow(line) {
        const match = line.match(/^throw\s+(.+);?$/);
        const argumentStr = match?.[1] || '';
        const argument = this.parseExpression(argumentStr) || {
            type: 'Identifier',
            name: 'exception',
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
        return {
            type: 'Throw',
            argument,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }
    parseIf(line) {
        const match = line.match(/^if\s*\((.+?)\)/);
        if (!match)
            return null;
        const conditionStr = match[1];
        const condition = this.parseExpression(conditionStr) || {
            type: 'Identifier',
            name: 'condition',
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
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
    parseFor(line) {
        // Enhanced for loop (for-each)
        const forEachMatch = line.match(/^for\s*\(\s*([\w<>,\[\]]+)\s+(\w+)\s*:\s*(.+?)\s*\)/);
        if (forEachMatch) {
            const variable = {
                type: 'VariableDeclaration',
                name: forEachMatch[2],
                varType: { name: forEachMatch[1] },
                kind: 'var',
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
            const iterable = this.parseExpression(forEachMatch[3]) || {
                type: 'Identifier',
                name: forEachMatch[3],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
            };
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
        // Traditional for loop
        const forMatch = line.match(/^for\s*\(\s*(.+?);\s*(.+?);\s*(.+?)\s*\)/);
        if (forMatch) {
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
        return null;
    }
    parseWhile(line) {
        const match = line.match(/^while\s*\((.+?)\)/);
        if (!match)
            return null;
        const test = this.parseExpression(match[1]) || {
            type: 'Identifier',
            name: 'condition',
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
        return {
            type: 'While',
            test,
            body: {
                type: 'Block',
                statements: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
            },
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }
    parseTry() {
        const startLine = this.currentLine;
        return {
            type: 'Try',
            body: {
                type: 'Block',
                statements: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, 0)
            },
            handlers: [],
            location: this.createLocation(startLine + 1, 0, this.currentLine + 1, 0)
        };
    }
    parseAssignment(line) {
        // Handle compound assignments
        const compoundMatch = line.match(/^([\w.\[\]]+)\s*([+\-*/&|^%]?=)\s*(.+?);?$/);
        if (!compoundMatch)
            return null;
        const leftStr = compoundMatch[1];
        const operator = compoundMatch[2];
        const rightStr = compoundMatch[3];
        const left = this.parseExpression(leftStr) || {
            type: 'Identifier',
            name: leftStr,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, leftStr.length)
        };
        const right = this.parseExpression(rightStr) || {
            type: 'Identifier',
            name: rightStr,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, rightStr.length)
        };
        return {
            type: 'Assignment',
            left,
            right,
            operator,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, line.length)
        };
    }
    parseExpression(expr) {
        const trimmed = expr.trim().replace(/;$/, '');
        if (!trimmed)
            return null;
        // String literal
        if ((trimmed.startsWith('"') && trimmed.endsWith('"'))) {
            return {
                type: 'StringLiteral',
                value: trimmed.slice(1, -1),
                raw: trimmed,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            };
        }
        // Number literal
        if (/^-?\d+(\.\d+)?[fFdDlL]?$/.test(trimmed)) {
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
            };
        }
        // Null literal
        if (trimmed === 'null') {
            return {
                type: 'NullLiteral',
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, trimmed.length)
            };
        }
        // New expression
        if (trimmed.startsWith('new ')) {
            return this.parseNewExpression(trimmed);
        }
        // Method call
        const callMatch = trimmed.match(/^([\w.]+)\s*\((.*)\)$/s);
        if (callMatch) {
            return this.parseCallExpression(callMatch[1], callMatch[2]);
        }
        // Member expression (obj.field)
        if (trimmed.includes('.') && !trimmed.includes('(')) {
            return this.parseMemberExpression(trimmed);
        }
        // Simple identifier
        if (/^[\w$]+$/.test(trimmed)) {
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
    parseNewExpression(expr) {
        const match = expr.match(/^new\s+([\w<>,\[\]]+)\s*(?:\((.*)?\))?/);
        if (!match) {
            return {
                type: 'NewExpression',
                callee: {
                    type: 'Identifier',
                    name: expr,
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
                },
                arguments: [],
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
            };
        }
        const className = match[1];
        const argsStr = match[2] || '';
        const args = [];
        if (argsStr.trim()) {
            const argsList = this.splitByComma(argsStr);
            for (const arg of argsList) {
                const parsed = this.parseExpression(arg.trim());
                if (parsed)
                    args.push(parsed);
            }
        }
        return {
            type: 'NewExpression',
            callee: {
                type: 'Identifier',
                name: className,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, className.length)
            },
            arguments: args,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
        };
    }
    parseCallExpression(calleeStr, argsStr) {
        let callee;
        if (calleeStr.includes('.')) {
            callee = this.parseMemberExpression(calleeStr);
        }
        else {
            callee = {
                type: 'Identifier',
                name: calleeStr,
                location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, calleeStr.length)
            };
        }
        const args = [];
        if (argsStr.trim()) {
            const argsList = this.splitByComma(argsStr);
            for (const arg of argsList) {
                const parsed = this.parseExpression(arg.trim());
                if (parsed)
                    args.push(parsed);
            }
        }
        return {
            type: 'CallExpression',
            callee,
            arguments: args,
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, calleeStr.length + argsStr.length + 2)
        };
    }
    parseMemberExpression(expr) {
        const parts = expr.split('.');
        if (parts.length < 2)
            return null;
        let current = {
            type: 'Identifier',
            name: parts[0],
            location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, parts[0].length)
        };
        for (let i = 1; i < parts.length; i++) {
            const part = parts[i];
            // Check for method call
            const methodMatch = part.match(/^(\w+)\s*\((.*)\)$/);
            if (methodMatch) {
                // Method call
                current = {
                    type: 'MemberExpression',
                    object: current,
                    property: {
                        type: 'Identifier',
                        name: methodMatch[1],
                        location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, methodMatch[1].length)
                    },
                    computed: false,
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
                };
                // Parse call expression
                const args = [];
                if (methodMatch[2].trim()) {
                    const argsList = this.splitByComma(methodMatch[2]);
                    for (const arg of argsList) {
                        const parsed = this.parseExpression(arg.trim());
                        if (parsed)
                            args.push(parsed);
                    }
                }
                current = {
                    type: 'CallExpression',
                    callee: current,
                    arguments: args,
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
                };
            }
            else {
                // Property access
                current = {
                    type: 'MemberExpression',
                    object: current,
                    property: {
                        type: 'Identifier',
                        name: part,
                        location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, part.length)
                    },
                    computed: false,
                    location: this.createLocation(this.currentLine + 1, 0, this.currentLine + 1, expr.length)
                };
            }
        }
        return current;
    }
    extractModifiers(line) {
        const modifiers = [];
        const modifierMap = {
            'public': 'public',
            'private': 'private',
            'protected': 'protected',
            'static': 'static',
            'final': 'final',
            'abstract': 'abstract',
            'synchronized': 'async', // Map synchronized to async conceptually
        };
        for (const [keyword, modifier] of Object.entries(modifierMap)) {
            if (new RegExp(`\\b${keyword}\\b`).test(line)) {
                modifiers.push(modifier);
            }
        }
        return modifiers;
    }
    splitByComma(str) {
        const result = [];
        let current = '';
        let depth = 0;
        for (const char of str) {
            if (char === '<' || char === '(' || char === '[' || char === '{') {
                depth++;
            }
            else if (char === '>' || char === ')' || char === ']' || char === '}') {
                depth--;
            }
            else if (char === ',' && depth === 0) {
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
exports.JavaParser = JavaParser;
function createJavaParser() {
    return new JavaParser();
}
//# sourceMappingURL=javaParser.js.map