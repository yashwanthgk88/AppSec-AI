"use strict";
/**
 * Python Parser
 *
 * Parses Python source code into the unified IR format for security analysis.
 * Uses regex-based parsing to extract security-relevant structures.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PythonParser = void 0;
exports.createPythonParser = createPythonParser;
const baseParser_1 = require("./baseParser");
class PythonParser extends baseParser_1.BaseParser {
    constructor() {
        super('python');
        this.context = null;
    }
    getSupportedExtensions() {
        return ['.py', '.pyw'];
    }
    async parse(source, filePath) {
        this.source = source;
        this.filePath = filePath;
        const lines = source.split('\n');
        this.context = {
            lines,
            currentLine: 0,
            indentStack: [0]
        };
        const imports = [];
        const body = [];
        let lineNum = 0;
        while (lineNum < lines.length) {
            const line = lines[lineNum];
            const trimmed = line.trim();
            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('#')) {
                lineNum++;
                continue;
            }
            // Parse imports
            if (trimmed.startsWith('import ') || trimmed.startsWith('from ')) {
                const importNode = this.parseImport(line, lineNum);
                if (importNode) {
                    imports.push(importNode);
                }
                lineNum++;
                continue;
            }
            // Parse class definitions
            if (trimmed.startsWith('class ')) {
                const { node, endLine } = this.parseClass(lines, lineNum);
                if (node) {
                    body.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            // Parse function definitions
            if (trimmed.startsWith('def ') || trimmed.startsWith('async def ')) {
                const { node, endLine } = this.parseFunction(lines, lineNum);
                if (node) {
                    body.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            // Parse variable assignments
            if (this.isAssignment(trimmed)) {
                const assignment = this.parseAssignment(line, lineNum);
                if (assignment) {
                    body.push(assignment);
                }
                lineNum++;
                continue;
            }
            // Parse expression statements (function calls, etc.)
            const expr = this.parseExpressionStatement(line, lineNum);
            if (expr) {
                body.push(expr);
            }
            lineNum++;
        }
        return {
            type: 'Program',
            language: 'python',
            imports,
            body,
            exports: [],
            location: this.createLocation(1, 0, lines.length, lines[lines.length - 1]?.length || 0)
        };
    }
    parseImport(line, lineNum) {
        const trimmed = line.trim();
        // from module import x, y, z
        const fromMatch = trimmed.match(/^from\s+([\w.]+)\s+import\s+(.+)$/);
        if (fromMatch) {
            const source = fromMatch[1];
            const importsStr = fromMatch[2];
            const specifiers = [];
            // Handle "from module import *"
            if (importsStr.trim() === '*') {
                specifiers.push({ local: '*', imported: '*' });
            }
            else {
                // Handle "from module import x, y as z"
                const parts = importsStr.split(',');
                for (const part of parts) {
                    const asMatch = part.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/);
                    if (asMatch) {
                        specifiers.push({
                            local: asMatch[2] || asMatch[1],
                            imported: asMatch[1]
                        });
                    }
                }
            }
            return {
                type: 'Import',
                source,
                specifiers,
                isNamespace: importsStr.trim() === '*',
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, line.length)
            };
        }
        // import module, module2 as alias
        const importMatch = trimmed.match(/^import\s+(.+)$/);
        if (importMatch) {
            const importsStr = importMatch[1];
            const specifiers = [];
            const parts = importsStr.split(',');
            for (const part of parts) {
                const asMatch = part.trim().match(/^([\w.]+)(?:\s+as\s+(\w+))?$/);
                if (asMatch) {
                    specifiers.push({
                        local: asMatch[2] || asMatch[1].split('.').pop(),
                        imported: asMatch[1]
                    });
                }
            }
            return {
                type: 'Import',
                source: specifiers[0]?.imported || '',
                specifiers,
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, line.length)
            };
        }
        return null;
    }
    parseClass(lines, startLine) {
        const line = lines[startLine];
        const trimmed = line.trim();
        // class ClassName(BaseClass, Interface):
        const classMatch = trimmed.match(/^class\s+(\w+)(?:\s*\(([^)]*)\))?\s*:/);
        if (!classMatch) {
            return { node: null, endLine: startLine };
        }
        const name = classMatch[1];
        const baseClassesStr = classMatch[2] || '';
        const baseClasses = baseClassesStr.split(',').map(b => b.trim()).filter(b => b);
        const superClass = baseClasses.length > 0 ? baseClasses[0] : undefined;
        const interfaces = baseClasses.slice(1);
        const baseIndent = this.getIndent(line);
        const members = [];
        let lineNum = startLine + 1;
        while (lineNum < lines.length) {
            const currentLine = lines[lineNum];
            const currentTrimmed = currentLine.trim();
            // Skip empty lines and comments
            if (!currentTrimmed || currentTrimmed.startsWith('#')) {
                lineNum++;
                continue;
            }
            const currentIndent = this.getIndent(currentLine);
            // End of class body
            if (currentIndent <= baseIndent && currentTrimmed) {
                lineNum--;
                break;
            }
            // Parse method
            if (currentTrimmed.startsWith('def ') || currentTrimmed.startsWith('async def ')) {
                const { node, endLine } = this.parseMethod(lines, lineNum, name);
                if (node) {
                    members.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            // Parse class variable
            if (this.isAssignment(currentTrimmed) && currentIndent === baseIndent + 4) {
                const prop = this.parseClassProperty(currentLine, lineNum);
                if (prop) {
                    members.push(prop);
                }
            }
            lineNum++;
        }
        return {
            node: {
                type: 'Class',
                name,
                superClass,
                interfaces,
                modifiers: [],
                members,
                location: this.createLocation(startLine + 1, 0, lineNum + 1, 0)
            },
            endLine: lineNum
        };
    }
    parseFunction(lines, startLine) {
        const line = lines[startLine];
        const trimmed = line.trim();
        const isAsync = trimmed.startsWith('async ');
        const funcMatch = trimmed.match(/^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*(\w+))?\s*:/);
        if (!funcMatch) {
            return { node: null, endLine: startLine };
        }
        const name = funcMatch[1];
        const paramsStr = funcMatch[2];
        const returnTypeStr = funcMatch[3];
        const parameters = this.parseParameters(paramsStr, startLine);
        const returnType = returnTypeStr ? { name: returnTypeStr } : undefined;
        const baseIndent = this.getIndent(line);
        const { body, endLine } = this.parseBlock(lines, startLine + 1, baseIndent);
        const modifiers = [];
        if (isAsync) {
            modifiers.push('async');
        }
        return {
            node: {
                type: 'Function',
                name,
                parameters,
                returnType,
                body,
                modifiers,
                isAsync,
                location: this.createLocation(startLine + 1, 0, endLine + 1, 0)
            },
            endLine
        };
    }
    parseMethod(lines, startLine, className) {
        const line = lines[startLine];
        const trimmed = line.trim();
        const isAsync = trimmed.startsWith('async ');
        const funcMatch = trimmed.match(/^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*(\w+))?\s*:/);
        if (!funcMatch) {
            return { node: null, endLine: startLine };
        }
        const name = funcMatch[1];
        const paramsStr = funcMatch[2];
        const returnTypeStr = funcMatch[3];
        const parameters = this.parseParameters(paramsStr, startLine);
        const returnType = returnTypeStr ? { name: returnTypeStr } : undefined;
        const baseIndent = this.getIndent(line);
        const { body, endLine } = this.parseBlock(lines, startLine + 1, baseIndent);
        const modifiers = [];
        if (isAsync) {
            modifiers.push('async');
        }
        // Check for decorators
        const isStatic = this.hasDecorator(lines, startLine, '@staticmethod');
        const isClassMethod = this.hasDecorator(lines, startLine, '@classmethod');
        if (isStatic) {
            modifiers.push('static');
        }
        // Check for private/protected naming conventions
        if (name.startsWith('__') && !name.endsWith('__')) {
            modifiers.push('private');
        }
        else if (name.startsWith('_')) {
            modifiers.push('protected');
        }
        return {
            node: {
                type: 'Method',
                name,
                parameters,
                returnType,
                body,
                modifiers,
                isAsync,
                isStatic,
                location: this.createLocation(startLine + 1, 0, endLine + 1, 0)
            },
            endLine
        };
    }
    parseParameters(paramsStr, lineNum) {
        const parameters = [];
        if (!paramsStr.trim()) {
            return parameters;
        }
        // Simple parameter parsing (doesn't handle all edge cases)
        const params = this.splitParameters(paramsStr);
        for (const param of params) {
            const trimmed = param.trim();
            if (!trimmed || trimmed === 'self' || trimmed === 'cls') {
                continue;
            }
            // Handle: name: Type = default
            const paramMatch = trimmed.match(/^(\*{0,2}\w+)(?:\s*:\s*([\w\[\],\s]+))?(?:\s*=\s*(.+))?$/);
            if (paramMatch) {
                const name = paramMatch[1];
                const typeStr = paramMatch[2];
                const defaultVal = paramMatch[3];
                const isRest = name.startsWith('*') && !name.startsWith('**');
                const cleanName = name.replace(/^\*+/, '');
                parameters.push({
                    type: 'Parameter',
                    name: cleanName,
                    paramType: typeStr ? { name: typeStr } : undefined,
                    isRest,
                    isOptional: !!defaultVal,
                    location: this.createLocation(lineNum + 1, 0, lineNum + 1, param.length)
                });
            }
        }
        return parameters;
    }
    splitParameters(paramsStr) {
        const params = [];
        let current = '';
        let depth = 0;
        for (const char of paramsStr) {
            if (char === '[' || char === '(' || char === '{') {
                depth++;
            }
            else if (char === ']' || char === ')' || char === '}') {
                depth--;
            }
            else if (char === ',' && depth === 0) {
                params.push(current);
                current = '';
                continue;
            }
            current += char;
        }
        if (current.trim()) {
            params.push(current);
        }
        return params;
    }
    parseBlock(lines, startLine, baseIndent) {
        const statements = [];
        let lineNum = startLine;
        while (lineNum < lines.length) {
            const line = lines[lineNum];
            const trimmed = line.trim();
            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('#')) {
                lineNum++;
                continue;
            }
            const currentIndent = this.getIndent(line);
            // End of block
            if (currentIndent <= baseIndent) {
                lineNum--;
                break;
            }
            // Parse nested structures
            if (trimmed.startsWith('def ') || trimmed.startsWith('async def ')) {
                const { node, endLine } = this.parseFunction(lines, lineNum);
                if (node) {
                    statements.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            if (trimmed.startsWith('if ')) {
                const { node, endLine } = this.parseIf(lines, lineNum);
                if (node) {
                    statements.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            if (trimmed.startsWith('for ')) {
                const { node, endLine } = this.parseFor(lines, lineNum);
                if (node) {
                    statements.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            if (trimmed.startsWith('while ')) {
                const { node, endLine } = this.parseWhile(lines, lineNum);
                if (node) {
                    statements.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            if (trimmed.startsWith('try:')) {
                const { node, endLine } = this.parseTry(lines, lineNum);
                if (node) {
                    statements.push(node);
                }
                lineNum = endLine + 1;
                continue;
            }
            if (trimmed.startsWith('return ') || trimmed === 'return') {
                const returnNode = this.parseReturn(line, lineNum);
                if (returnNode) {
                    statements.push(returnNode);
                }
                lineNum++;
                continue;
            }
            // Parse expression or assignment
            if (this.isAssignment(trimmed)) {
                const assignment = this.parseAssignment(line, lineNum);
                if (assignment) {
                    statements.push(assignment);
                }
            }
            else {
                const expr = this.parseExpressionStatement(line, lineNum);
                if (expr) {
                    statements.push(expr);
                }
            }
            lineNum++;
        }
        return {
            body: {
                type: 'Block',
                statements,
                location: this.createLocation(startLine + 1, 0, lineNum + 1, 0)
            },
            endLine: lineNum
        };
    }
    parseIf(lines, startLine) {
        const line = lines[startLine];
        const trimmed = line.trim();
        const ifMatch = trimmed.match(/^if\s+(.+):\s*$/);
        if (!ifMatch) {
            return { node: null, endLine: startLine };
        }
        const condition = this.parseExpression(ifMatch[1], startLine);
        const baseIndent = this.getIndent(line);
        const { body: thenBranch, endLine: thenEnd } = this.parseBlock(lines, startLine + 1, baseIndent);
        let elseBranch;
        let endLine = thenEnd;
        // Check for elif/else
        if (thenEnd + 1 < lines.length) {
            const nextLine = lines[thenEnd + 1];
            const nextTrimmed = nextLine.trim();
            if (nextTrimmed.startsWith('elif ')) {
                const { node: elifNode, endLine: elifEnd } = this.parseIf(lines, thenEnd + 1);
                if (elifNode) {
                    elseBranch = elifNode;
                    endLine = elifEnd;
                }
            }
            else if (nextTrimmed.startsWith('else:')) {
                const { body: elseBody, endLine: elseEnd } = this.parseBlock(lines, thenEnd + 2, baseIndent);
                elseBranch = elseBody;
                endLine = elseEnd;
            }
        }
        return {
            node: {
                type: 'If',
                condition: condition,
                thenBranch,
                elseBranch,
                location: this.createLocation(startLine + 1, 0, endLine + 1, 0)
            },
            endLine
        };
    }
    parseFor(lines, startLine) {
        const line = lines[startLine];
        const trimmed = line.trim();
        const forMatch = trimmed.match(/^for\s+(\w+)\s+in\s+(.+):\s*$/);
        if (!forMatch) {
            return { node: null, endLine: startLine };
        }
        const variable = {
            type: 'Identifier',
            name: forMatch[1],
            location: this.createLocation(startLine + 1, 0, startLine + 1, forMatch[1].length)
        };
        const iterable = this.parseExpression(forMatch[2], startLine);
        const baseIndent = this.getIndent(line);
        const { body, endLine } = this.parseBlock(lines, startLine + 1, baseIndent);
        return {
            node: {
                type: 'ForEach',
                variable,
                iterable: iterable,
                body,
                location: this.createLocation(startLine + 1, 0, endLine + 1, 0)
            },
            endLine
        };
    }
    parseWhile(lines, startLine) {
        const line = lines[startLine];
        const trimmed = line.trim();
        const whileMatch = trimmed.match(/^while\s+(.+):\s*$/);
        if (!whileMatch) {
            return { node: null, endLine: startLine };
        }
        const test = this.parseExpression(whileMatch[1], startLine);
        const baseIndent = this.getIndent(line);
        const { body, endLine } = this.parseBlock(lines, startLine + 1, baseIndent);
        return {
            node: {
                type: 'While',
                test: test,
                body,
                location: this.createLocation(startLine + 1, 0, endLine + 1, 0)
            },
            endLine
        };
    }
    parseTry(lines, startLine) {
        const line = lines[startLine];
        const baseIndent = this.getIndent(line);
        const { body, endLine: tryEnd } = this.parseBlock(lines, startLine + 1, baseIndent);
        const handlers = [];
        let finalizer;
        let endLine = tryEnd;
        // Parse except clauses
        let lineNum = tryEnd + 1;
        while (lineNum < lines.length) {
            const currentLine = lines[lineNum];
            const trimmed = currentLine.trim();
            if (trimmed.startsWith('except')) {
                const exceptMatch = trimmed.match(/^except(?:\s+(\w+)(?:\s+as\s+(\w+))?)?\s*:/);
                if (exceptMatch) {
                    const { body: catchBody, endLine: catchEnd } = this.parseBlock(lines, lineNum + 1, baseIndent);
                    const param = exceptMatch[2] ? {
                        type: 'Parameter',
                        name: exceptMatch[2],
                        paramType: exceptMatch[1] ? { name: exceptMatch[1] } : undefined,
                        location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
                    } : undefined;
                    handlers.push({
                        type: 'Catch',
                        param,
                        body: catchBody,
                        location: this.createLocation(lineNum + 1, 0, catchEnd + 1, 0)
                    });
                    lineNum = catchEnd + 1;
                    endLine = catchEnd;
                    continue;
                }
            }
            if (trimmed.startsWith('finally:')) {
                const { body: finallyBody, endLine: finallyEnd } = this.parseBlock(lines, lineNum + 1, baseIndent);
                finalizer = finallyBody;
                endLine = finallyEnd;
                break;
            }
            // If we hit something that's not except/finally, we're done
            if (trimmed && this.getIndent(currentLine) <= baseIndent) {
                lineNum--;
                break;
            }
            lineNum++;
        }
        return {
            node: {
                type: 'Try',
                body,
                handlers,
                finalizer,
                location: this.createLocation(startLine + 1, 0, endLine + 1, 0)
            },
            endLine
        };
    }
    parseReturn(line, lineNum) {
        const trimmed = line.trim();
        const returnMatch = trimmed.match(/^return\s*(.*)$/);
        const argument = returnMatch && returnMatch[1]
            ? this.parseExpression(returnMatch[1], lineNum)
            : undefined;
        return {
            type: 'Return',
            argument: argument || undefined,
            location: this.createLocation(lineNum + 1, 0, lineNum + 1, line.length)
        };
    }
    parseAssignment(line, lineNum) {
        const trimmed = line.trim();
        // Handle augmented assignment (+=, -=, etc.)
        const augmentedMatch = trimmed.match(/^(\w+)\s*([+\-*/|&^%]=)\s*(.+)$/);
        if (augmentedMatch) {
            const left = {
                type: 'Identifier',
                name: augmentedMatch[1],
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, augmentedMatch[1].length)
            };
            const right = this.parseExpression(augmentedMatch[3], lineNum);
            return {
                type: 'Assignment',
                left,
                right: right,
                operator: augmentedMatch[2],
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, line.length)
            };
        }
        // Handle regular assignment with optional type annotation
        const assignMatch = trimmed.match(/^(\w+)(?:\s*:\s*([\w\[\],\s]+))?\s*=\s*(.+)$/);
        if (assignMatch) {
            const name = assignMatch[1];
            const typeStr = assignMatch[2];
            const valueStr = assignMatch[3];
            const initializer = this.parseExpression(valueStr, lineNum);
            const varType = typeStr ? { name: typeStr } : undefined;
            return {
                type: 'VariableDeclaration',
                name,
                varType,
                initializer: initializer || undefined,
                kind: 'var',
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, line.length)
            };
        }
        return null;
    }
    parseClassProperty(line, lineNum) {
        const trimmed = line.trim();
        const assignMatch = trimmed.match(/^(\w+)(?:\s*:\s*([\w\[\],\s]+))?\s*=\s*(.+)$/);
        if (assignMatch) {
            const name = assignMatch[1];
            const typeStr = assignMatch[2];
            const valueStr = assignMatch[3];
            const initializer = this.parseExpression(valueStr, lineNum);
            const valueType = typeStr ? { name: typeStr } : undefined;
            return {
                type: 'Property',
                name,
                valueType,
                initializer: initializer || undefined,
                modifiers: [],
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, line.length)
            };
        }
        return null;
    }
    parseExpressionStatement(line, lineNum) {
        const trimmed = line.trim();
        // Check for function call
        const callMatch = trimmed.match(/^([\w.]+)\s*\((.*)$/);
        if (callMatch) {
            return this.parseCallExpression(trimmed, lineNum);
        }
        return this.parseExpression(trimmed, lineNum);
    }
    parseExpression(expr, lineNum) {
        const trimmed = expr.trim();
        if (!trimmed) {
            return null;
        }
        // String literal
        if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
            (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
            return {
                type: 'StringLiteral',
                value: trimmed.slice(1, -1),
                raw: trimmed,
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
            };
        }
        // F-string
        if (trimmed.startsWith('f"') || trimmed.startsWith("f'")) {
            return {
                type: 'TemplateLiteral',
                quasis: [{
                        type: 'StringLiteral',
                        value: trimmed.slice(2, -1),
                        raw: trimmed,
                        location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
                    }],
                expressions: [],
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
            };
        }
        // Number literal
        if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
            return {
                type: 'NumberLiteral',
                value: parseFloat(trimmed),
                raw: trimmed,
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
            };
        }
        // Boolean literals
        if (trimmed === 'True' || trimmed === 'False') {
            return {
                type: 'BooleanLiteral',
                value: trimmed === 'True',
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
            };
        }
        // None literal
        if (trimmed === 'None') {
            return {
                type: 'NullLiteral',
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
            };
        }
        // Function call
        const callMatch = trimmed.match(/^([\w.]+)\s*\((.*)$/);
        if (callMatch) {
            return this.parseCallExpression(trimmed, lineNum);
        }
        // Member expression (obj.attr)
        if (trimmed.includes('.') && !trimmed.includes('(')) {
            const parts = trimmed.split('.');
            let current = {
                type: 'Identifier',
                name: parts[0],
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, parts[0].length)
            };
            for (let i = 1; i < parts.length; i++) {
                current = {
                    type: 'MemberExpression',
                    object: current,
                    property: {
                        type: 'Identifier',
                        name: parts[i],
                        location: this.createLocation(lineNum + 1, 0, lineNum + 1, parts[i].length)
                    },
                    computed: false,
                    location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
                };
            }
            return current;
        }
        // Simple identifier
        if (/^\w+$/.test(trimmed)) {
            return {
                type: 'Identifier',
                name: trimmed,
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
            };
        }
        // Binary expression (simple detection)
        const binaryOps = ['and', 'or', 'not', '+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=', 'in', 'is'];
        for (const op of binaryOps) {
            const opPattern = new RegExp(`\\s+${op.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+`);
            const parts = trimmed.split(opPattern);
            if (parts.length === 2) {
                return {
                    type: 'BinaryExpression',
                    operator: op,
                    left: this.parseExpression(parts[0], lineNum),
                    right: this.parseExpression(parts[1], lineNum),
                    location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
                };
            }
        }
        // Default to identifier
        return {
            type: 'Identifier',
            name: trimmed,
            location: this.createLocation(lineNum + 1, 0, lineNum + 1, trimmed.length)
        };
    }
    parseCallExpression(expr, lineNum) {
        // Match function/method call
        const callMatch = expr.match(/^([\w.]+)\s*\((.*)\)$/s);
        if (!callMatch) {
            return null;
        }
        const calleeStr = callMatch[1];
        const argsStr = callMatch[2];
        let callee;
        if (calleeStr.includes('.')) {
            const parts = calleeStr.split('.');
            let current = {
                type: 'Identifier',
                name: parts[0],
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, parts[0].length)
            };
            for (let i = 1; i < parts.length; i++) {
                current = {
                    type: 'MemberExpression',
                    object: current,
                    property: {
                        type: 'Identifier',
                        name: parts[i],
                        location: this.createLocation(lineNum + 1, 0, lineNum + 1, parts[i].length)
                    },
                    computed: false,
                    location: this.createLocation(lineNum + 1, 0, lineNum + 1, calleeStr.length)
                };
            }
            callee = current;
        }
        else {
            callee = {
                type: 'Identifier',
                name: calleeStr,
                location: this.createLocation(lineNum + 1, 0, lineNum + 1, calleeStr.length)
            };
        }
        const args = [];
        if (argsStr.trim()) {
            const argsList = this.splitParameters(argsStr);
            for (const arg of argsList) {
                const parsed = this.parseExpression(arg.trim(), lineNum);
                if (parsed) {
                    args.push(parsed);
                }
            }
        }
        return {
            type: 'CallExpression',
            callee,
            arguments: args,
            location: this.createLocation(lineNum + 1, 0, lineNum + 1, expr.length)
        };
    }
    isAssignment(line) {
        const trimmed = line.trim();
        // Check for assignment but not comparison
        return /^[\w.]+(?:\s*:\s*[\w\[\],\s]+)?\s*[+\-*/|&^%]?=(?!=)/.test(trimmed);
    }
    getIndent(line) {
        const match = line.match(/^(\s*)/);
        return match ? match[1].length : 0;
    }
    hasDecorator(lines, funcLine, decorator) {
        let lineNum = funcLine - 1;
        while (lineNum >= 0) {
            const line = lines[lineNum].trim();
            if (line.startsWith('@')) {
                if (line.startsWith(decorator)) {
                    return true;
                }
                lineNum--;
            }
            else {
                break;
            }
        }
        return false;
    }
}
exports.PythonParser = PythonParser;
function createPythonParser() {
    return new PythonParser();
}
//# sourceMappingURL=pythonParser.js.map