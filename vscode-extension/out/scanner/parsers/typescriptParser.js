"use strict";
/**
 * TypeScript/JavaScript Parser
 *
 * Parses TypeScript and JavaScript source code into the unified IR format
 * using the TypeScript compiler API.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.TypeScriptParser = void 0;
exports.createJavaScriptParser = createJavaScriptParser;
exports.createTypeScriptParser = createTypeScriptParser;
const ts = __importStar(require("typescript"));
const baseParser_1 = require("./baseParser");
class TypeScriptParser extends baseParser_1.BaseParser {
    constructor(isTypeScript = true) {
        super(isTypeScript ? 'typescript' : 'javascript');
        this.sourceFile = null;
    }
    getSupportedExtensions() {
        return this.language === 'typescript'
            ? ['.ts', '.tsx']
            : ['.js', '.jsx', '.mjs', '.cjs'];
    }
    async parse(source, filePath) {
        this.source = source;
        this.filePath = filePath;
        const scriptKind = this.getScriptKind(filePath);
        this.sourceFile = ts.createSourceFile(filePath, source, ts.ScriptTarget.Latest, true, scriptKind);
        const imports = [];
        const exports = [];
        const body = [];
        for (const statement of this.sourceFile.statements) {
            if (ts.isImportDeclaration(statement)) {
                const importNode = this.parseImportDeclaration(statement);
                if (importNode) {
                    imports.push(importNode);
                }
            }
            else if (ts.isExportDeclaration(statement) || ts.isExportAssignment(statement)) {
                const exportNode = this.parseExportDeclaration(statement);
                if (exportNode) {
                    exports.push(exportNode);
                }
            }
            else {
                const node = this.parseStatement(statement);
                if (node) {
                    body.push(node);
                }
            }
        }
        return {
            type: 'Program',
            language: this.language,
            imports,
            body,
            exports,
            location: this.getNodeLocation(this.sourceFile)
        };
    }
    getScriptKind(filePath) {
        if (filePath.endsWith('.tsx')) {
            return ts.ScriptKind.TSX;
        }
        if (filePath.endsWith('.ts')) {
            return ts.ScriptKind.TS;
        }
        if (filePath.endsWith('.jsx')) {
            return ts.ScriptKind.JSX;
        }
        return ts.ScriptKind.JS;
    }
    // ========================================================================
    // Statement Parsing
    // ========================================================================
    parseStatement(node) {
        if (ts.isFunctionDeclaration(node)) {
            return this.parseFunctionDeclaration(node);
        }
        if (ts.isClassDeclaration(node)) {
            return this.parseClassDeclaration(node);
        }
        if (ts.isVariableStatement(node)) {
            return this.parseVariableStatement(node);
        }
        if (ts.isExpressionStatement(node)) {
            return this.parseExpression(node.expression);
        }
        if (ts.isIfStatement(node)) {
            return this.parseIfStatement(node);
        }
        if (ts.isForStatement(node)) {
            return this.parseForStatement(node);
        }
        if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
            return this.parseForEachStatement(node);
        }
        if (ts.isWhileStatement(node)) {
            return this.parseWhileStatement(node);
        }
        if (ts.isDoStatement(node)) {
            return this.parseDoWhileStatement(node);
        }
        if (ts.isTryStatement(node)) {
            return this.parseTryStatement(node);
        }
        if (ts.isReturnStatement(node)) {
            return this.parseReturnStatement(node);
        }
        if (ts.isThrowStatement(node)) {
            return this.parseThrowStatement(node);
        }
        if (ts.isSwitchStatement(node)) {
            return this.parseSwitchStatement(node);
        }
        if (ts.isBlock(node)) {
            return this.parseBlock(node);
        }
        return null;
    }
    parseFunctionDeclaration(node) {
        if (!node.name) {
            return null;
        }
        const name = node.name.getText(this.sourceFile);
        const parameters = node.parameters.map(p => this.parseParameter(p));
        const returnType = node.type ? this.parseType(node.type) : undefined;
        const modifiers = this.parseModifiers(node);
        const body = node.body ? this.parseBlock(node.body) : this.createBlock([], this.getNodeLocation(node));
        return {
            type: 'Function',
            name,
            parameters,
            returnType,
            body,
            modifiers,
            isAsync: modifiers.includes('async'),
            location: this.getNodeLocation(node)
        };
    }
    parseClassDeclaration(node) {
        const name = node.name?.getText(this.sourceFile) || 'AnonymousClass';
        const modifiers = this.parseModifiers(node);
        const members = [];
        let superClass;
        const interfaces = [];
        if (node.heritageClauses) {
            for (const clause of node.heritageClauses) {
                if (clause.token === ts.SyntaxKind.ExtendsKeyword) {
                    superClass = clause.types[0]?.getText(this.sourceFile);
                }
                else if (clause.token === ts.SyntaxKind.ImplementsKeyword) {
                    interfaces.push(...clause.types.map(t => t.getText(this.sourceFile)));
                }
            }
        }
        for (const member of node.members) {
            if (ts.isMethodDeclaration(member)) {
                const method = this.parseMethodDeclaration(member);
                if (method) {
                    members.push(method);
                }
            }
            else if (ts.isPropertyDeclaration(member)) {
                const prop = this.parsePropertyDeclaration(member);
                if (prop) {
                    members.push(prop);
                }
            }
            else if (ts.isConstructorDeclaration(member)) {
                const ctor = this.parseConstructorDeclaration(member);
                if (ctor) {
                    members.push(ctor);
                }
            }
        }
        return {
            type: 'Class',
            name,
            superClass,
            interfaces,
            modifiers,
            members,
            isAbstract: modifiers.includes('abstract'),
            location: this.getNodeLocation(node)
        };
    }
    parseMethodDeclaration(node) {
        const name = node.name.getText(this.sourceFile);
        const parameters = node.parameters.map(p => this.parseParameter(p));
        const returnType = node.type ? this.parseType(node.type) : undefined;
        const modifiers = this.parseModifiers(node);
        const body = node.body ? this.parseBlock(node.body) : undefined;
        return {
            type: 'Method',
            name,
            parameters,
            returnType,
            body,
            modifiers,
            isAsync: modifiers.includes('async'),
            isStatic: modifiers.includes('static'),
            isAbstract: modifiers.includes('abstract'),
            location: this.getNodeLocation(node)
        };
    }
    parsePropertyDeclaration(node) {
        const name = node.name.getText(this.sourceFile);
        const modifiers = this.parseModifiers(node);
        const valueType = node.type ? this.parseType(node.type) : undefined;
        const initializer = node.initializer ? this.parseExpression(node.initializer) : undefined;
        return {
            type: 'Property',
            name,
            valueType,
            initializer: initializer || undefined,
            modifiers,
            isStatic: modifiers.includes('static'),
            location: this.getNodeLocation(node)
        };
    }
    parseConstructorDeclaration(node) {
        const parameters = node.parameters.map(p => this.parseParameter(p));
        const modifiers = this.parseModifiers(node);
        const body = node.body ? this.parseBlock(node.body) : this.createBlock([], this.getNodeLocation(node));
        return {
            type: 'Constructor',
            parameters,
            body,
            modifiers,
            location: this.getNodeLocation(node)
        };
    }
    parseParameter(node) {
        const name = node.name.getText(this.sourceFile);
        const paramType = node.type ? this.parseType(node.type) : undefined;
        const defaultValue = node.initializer ? this.parseExpression(node.initializer) : undefined;
        return {
            type: 'Parameter',
            name,
            paramType,
            defaultValue: defaultValue || undefined,
            isOptional: !!node.questionToken,
            isRest: !!node.dotDotDotToken,
            location: this.getNodeLocation(node)
        };
    }
    parseVariableStatement(node) {
        const declarations = [];
        const kind = this.getVariableKind(node.declarationList);
        for (const decl of node.declarationList.declarations) {
            const name = decl.name.getText(this.sourceFile);
            const varType = decl.type ? this.parseType(decl.type) : undefined;
            const initializer = decl.initializer ? this.parseExpression(decl.initializer) : undefined;
            declarations.push({
                type: 'VariableDeclaration',
                name,
                varType,
                initializer: initializer || undefined,
                kind,
                location: this.getNodeLocation(decl)
            });
        }
        // Return single declaration or block of declarations
        if (declarations.length === 1) {
            return declarations[0];
        }
        return {
            type: 'Block',
            statements: declarations,
            location: this.getNodeLocation(node)
        };
    }
    parseIfStatement(node) {
        const condition = this.parseExpression(node.expression);
        const thenBranch = ts.isBlock(node.thenStatement)
            ? this.parseBlock(node.thenStatement)
            : this.createBlock([this.parseStatement(node.thenStatement)], this.getNodeLocation(node.thenStatement));
        let elseBranch;
        if (node.elseStatement) {
            if (ts.isIfStatement(node.elseStatement)) {
                elseBranch = this.parseIfStatement(node.elseStatement);
            }
            else if (ts.isBlock(node.elseStatement)) {
                elseBranch = this.parseBlock(node.elseStatement);
            }
            else {
                elseBranch = this.createBlock([this.parseStatement(node.elseStatement)], this.getNodeLocation(node.elseStatement));
            }
        }
        return {
            type: 'If',
            condition,
            thenBranch,
            elseBranch,
            location: this.getNodeLocation(node)
        };
    }
    parseForStatement(node) {
        const init = node.initializer ? this.parseForInitializer(node.initializer) : undefined;
        const test = node.condition ? this.parseExpression(node.condition) : undefined;
        const update = node.incrementor ? this.parseExpression(node.incrementor) : undefined;
        const body = ts.isBlock(node.statement)
            ? this.parseBlock(node.statement)
            : this.createBlock([this.parseStatement(node.statement)], this.getNodeLocation(node.statement));
        return {
            type: 'For',
            init: init || undefined,
            test: test || undefined,
            update: update || undefined,
            body,
            location: this.getNodeLocation(node)
        };
    }
    parseForEachStatement(node) {
        const variable = this.parseForInitializer(node.initializer);
        const iterable = this.parseExpression(node.expression);
        const body = ts.isBlock(node.statement)
            ? this.parseBlock(node.statement)
            : this.createBlock([this.parseStatement(node.statement)], this.getNodeLocation(node.statement));
        return {
            type: 'ForEach',
            variable,
            iterable,
            body,
            location: this.getNodeLocation(node)
        };
    }
    parseWhileStatement(node) {
        const test = this.parseExpression(node.expression);
        const body = ts.isBlock(node.statement)
            ? this.parseBlock(node.statement)
            : this.createBlock([this.parseStatement(node.statement)], this.getNodeLocation(node.statement));
        return {
            type: 'While',
            test,
            body,
            location: this.getNodeLocation(node)
        };
    }
    parseDoWhileStatement(node) {
        const test = this.parseExpression(node.expression);
        const body = ts.isBlock(node.statement)
            ? this.parseBlock(node.statement)
            : this.createBlock([this.parseStatement(node.statement)], this.getNodeLocation(node.statement));
        return {
            type: 'DoWhile',
            test,
            body,
            location: this.getNodeLocation(node)
        };
    }
    parseTryStatement(node) {
        const body = this.parseBlock(node.tryBlock);
        const handlers = [];
        if (node.catchClause) {
            const catchParam = node.catchClause.variableDeclaration
                ? this.parseParameter(node.catchClause.variableDeclaration)
                : undefined;
            handlers.push({
                type: 'Catch',
                param: catchParam,
                body: this.parseBlock(node.catchClause.block),
                location: this.getNodeLocation(node.catchClause)
            });
        }
        const finalizer = node.finallyBlock ? this.parseBlock(node.finallyBlock) : undefined;
        return {
            type: 'Try',
            body,
            handlers,
            finalizer,
            location: this.getNodeLocation(node)
        };
    }
    parseReturnStatement(node) {
        const argument = node.expression ? this.parseExpression(node.expression) : undefined;
        return {
            type: 'Return',
            argument: argument || undefined,
            location: this.getNodeLocation(node)
        };
    }
    parseThrowStatement(node) {
        const argument = this.parseExpression(node.expression);
        return {
            type: 'Throw',
            argument,
            location: this.getNodeLocation(node)
        };
    }
    parseSwitchStatement(node) {
        const discriminant = this.parseExpression(node.expression);
        const cases = [];
        for (const clause of node.caseBlock.clauses) {
            const test = ts.isCaseClause(clause)
                ? this.parseExpression(clause.expression)
                : null;
            const consequent = [];
            for (const stmt of clause.statements) {
                const parsed = this.parseStatement(stmt);
                if (parsed) {
                    consequent.push(parsed);
                }
            }
            cases.push({
                type: 'Case',
                test,
                consequent,
                location: this.getNodeLocation(clause)
            });
        }
        return {
            type: 'Switch',
            discriminant,
            cases,
            location: this.getNodeLocation(node)
        };
    }
    parseBlock(node) {
        const statements = [];
        for (const stmt of node.statements) {
            const parsed = this.parseStatement(stmt);
            if (parsed) {
                statements.push(parsed);
            }
        }
        return {
            type: 'Block',
            statements,
            location: this.getNodeLocation(node)
        };
    }
    // ========================================================================
    // Expression Parsing
    // ========================================================================
    parseExpression(node) {
        if (ts.isIdentifier(node)) {
            return this.parseIdentifier(node);
        }
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
            return this.parseStringLiteral(node);
        }
        if (ts.isNumericLiteral(node)) {
            return this.parseNumericLiteral(node);
        }
        if (ts.isTemplateExpression(node)) {
            return this.parseTemplateExpression(node);
        }
        if (ts.isCallExpression(node)) {
            return this.parseCallExpression(node);
        }
        if (ts.isPropertyAccessExpression(node)) {
            return this.parsePropertyAccessExpression(node);
        }
        if (ts.isElementAccessExpression(node)) {
            return this.parseElementAccessExpression(node);
        }
        if (ts.isBinaryExpression(node)) {
            return this.parseBinaryExpression(node);
        }
        if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
            return this.parseUnaryExpression(node);
        }
        if (ts.isNewExpression(node)) {
            return this.parseNewExpression(node);
        }
        if (ts.isConditionalExpression(node)) {
            return this.parseConditionalExpression(node);
        }
        if (ts.isArrayLiteralExpression(node)) {
            return this.parseArrayLiteral(node);
        }
        if (ts.isObjectLiteralExpression(node)) {
            return this.parseObjectLiteral(node);
        }
        if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
            return this.parseFunctionExpression(node);
        }
        if (ts.isAwaitExpression(node)) {
            return this.parseExpression(node.expression);
        }
        if (ts.isParenthesizedExpression(node)) {
            return this.parseExpression(node.expression);
        }
        if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) {
            return {
                type: 'BooleanLiteral',
                value: node.kind === ts.SyntaxKind.TrueKeyword,
                location: this.getNodeLocation(node)
            };
        }
        if (node.kind === ts.SyntaxKind.NullKeyword) {
            return {
                type: 'NullLiteral',
                location: this.getNodeLocation(node)
            };
        }
        return null;
    }
    parseIdentifier(node) {
        return {
            type: 'Identifier',
            name: node.getText(this.sourceFile),
            location: this.getNodeLocation(node)
        };
    }
    parseStringLiteral(node) {
        return {
            type: 'StringLiteral',
            value: node.text,
            raw: node.getText(this.sourceFile),
            location: this.getNodeLocation(node)
        };
    }
    parseNumericLiteral(node) {
        return {
            type: 'NumberLiteral',
            value: parseFloat(node.text),
            raw: node.getText(this.sourceFile),
            location: this.getNodeLocation(node)
        };
    }
    parseTemplateExpression(node) {
        const quasis = [];
        const expressions = [];
        // Head
        quasis.push({
            type: 'StringLiteral',
            value: node.head.text,
            raw: node.head.rawText || node.head.text,
            location: this.getNodeLocation(node.head)
        });
        for (const span of node.templateSpans) {
            const expr = this.parseExpression(span.expression);
            if (expr) {
                expressions.push(expr);
            }
            quasis.push({
                type: 'StringLiteral',
                value: span.literal.text,
                raw: span.literal.rawText || span.literal.text,
                location: this.getNodeLocation(span.literal)
            });
        }
        return {
            type: 'TemplateLiteral',
            quasis,
            expressions,
            location: this.getNodeLocation(node)
        };
    }
    parseCallExpression(node) {
        const callee = this.parseExpression(node.expression);
        const args = [];
        for (const arg of node.arguments) {
            const parsed = this.parseExpression(arg);
            if (parsed) {
                args.push(parsed);
            }
        }
        return {
            type: 'CallExpression',
            callee,
            arguments: args,
            isOptional: !!node.questionDotToken,
            location: this.getNodeLocation(node)
        };
    }
    parsePropertyAccessExpression(node) {
        const object = this.parseExpression(node.expression);
        const propertyName = node.name.getText(this.sourceFile);
        const property = {
            type: 'Identifier',
            name: propertyName,
            location: this.getNodeLocation(node.name)
        };
        return {
            type: 'MemberExpression',
            object,
            property,
            computed: false,
            isOptional: !!node.questionDotToken,
            location: this.getNodeLocation(node)
        };
    }
    parseElementAccessExpression(node) {
        const object = this.parseExpression(node.expression);
        const property = this.parseExpression(node.argumentExpression);
        return {
            type: 'MemberExpression',
            object,
            property,
            computed: true,
            isOptional: !!node.questionDotToken,
            location: this.getNodeLocation(node)
        };
    }
    parseBinaryExpression(node) {
        const operator = this.getBinaryOperator(node.operatorToken.kind);
        const left = this.parseExpression(node.left);
        const right = this.parseExpression(node.right);
        // Check if this is an assignment
        if (this.isAssignmentOperator(node.operatorToken.kind)) {
            return {
                type: 'Assignment',
                left,
                right,
                operator,
                location: this.getNodeLocation(node)
            };
        }
        return {
            type: 'BinaryExpression',
            operator,
            left,
            right,
            location: this.getNodeLocation(node)
        };
    }
    parseUnaryExpression(node) {
        const operator = this.getUnaryOperator(node.operator);
        const argument = this.parseExpression(node.operand);
        const prefix = ts.isPrefixUnaryExpression(node);
        return {
            type: 'UnaryExpression',
            operator,
            argument,
            prefix,
            location: this.getNodeLocation(node)
        };
    }
    parseNewExpression(node) {
        const callee = this.parseExpression(node.expression);
        const args = [];
        if (node.arguments) {
            for (const arg of node.arguments) {
                const parsed = this.parseExpression(arg);
                if (parsed) {
                    args.push(parsed);
                }
            }
        }
        return {
            type: 'NewExpression',
            callee,
            arguments: args,
            location: this.getNodeLocation(node)
        };
    }
    parseConditionalExpression(node) {
        return {
            type: 'ConditionalExpression',
            test: this.parseExpression(node.condition),
            consequent: this.parseExpression(node.whenTrue),
            alternate: this.parseExpression(node.whenFalse),
            location: this.getNodeLocation(node)
        };
    }
    parseArrayLiteral(node) {
        const elements = [];
        for (const elem of node.elements) {
            const parsed = this.parseExpression(elem);
            if (parsed) {
                elements.push(parsed);
            }
        }
        return {
            type: 'ArrayLiteral',
            elements,
            location: this.getNodeLocation(node)
        };
    }
    parseObjectLiteral(node) {
        const properties = [];
        for (const prop of node.properties) {
            if (ts.isPropertyAssignment(prop)) {
                const name = prop.name.getText(this.sourceFile);
                const initializer = this.parseExpression(prop.initializer);
                properties.push({
                    type: 'Property',
                    name,
                    initializer: initializer || undefined,
                    modifiers: [],
                    location: this.getNodeLocation(prop)
                });
            }
            else if (ts.isShorthandPropertyAssignment(prop)) {
                const name = prop.name.getText(this.sourceFile);
                properties.push({
                    type: 'Property',
                    name,
                    initializer: this.parseIdentifier(prop.name),
                    modifiers: [],
                    location: this.getNodeLocation(prop)
                });
            }
        }
        return {
            type: 'ObjectLiteral',
            properties,
            location: this.getNodeLocation(node)
        };
    }
    parseFunctionExpression(node) {
        const name = ts.isFunctionExpression(node) && node.name
            ? node.name.getText(this.sourceFile)
            : '<anonymous>';
        const parameters = node.parameters.map(p => this.parseParameter(p));
        const returnType = node.type ? this.parseType(node.type) : undefined;
        const modifiers = this.parseModifiers(node);
        let body;
        if (ts.isBlock(node.body)) {
            body = this.parseBlock(node.body);
        }
        else {
            const expr = this.parseExpression(node.body);
            body = this.createBlock(expr ? [{
                    type: 'Return',
                    argument: expr,
                    location: this.getNodeLocation(node.body)
                }] : [], this.getNodeLocation(node.body));
        }
        return {
            type: 'Function',
            name,
            parameters,
            returnType,
            body,
            modifiers,
            isAsync: modifiers.includes('async'),
            location: this.getNodeLocation(node)
        };
    }
    // ========================================================================
    // Import/Export Parsing
    // ========================================================================
    parseImportDeclaration(node) {
        const source = node.moduleSpecifier.text;
        const specifiers = [];
        let isDefault = false;
        let isNamespace = false;
        if (node.importClause) {
            // Default import
            if (node.importClause.name) {
                specifiers.push({
                    local: node.importClause.name.getText(this.sourceFile),
                    imported: 'default'
                });
                isDefault = true;
            }
            // Named imports
            if (node.importClause.namedBindings) {
                if (ts.isNamespaceImport(node.importClause.namedBindings)) {
                    specifiers.push({
                        local: node.importClause.namedBindings.name.getText(this.sourceFile),
                        imported: '*'
                    });
                    isNamespace = true;
                }
                else if (ts.isNamedImports(node.importClause.namedBindings)) {
                    for (const elem of node.importClause.namedBindings.elements) {
                        specifiers.push({
                            local: elem.name.getText(this.sourceFile),
                            imported: elem.propertyName?.getText(this.sourceFile) || elem.name.getText(this.sourceFile)
                        });
                    }
                }
            }
        }
        return {
            type: 'Import',
            source,
            specifiers,
            isDefault,
            isNamespace,
            location: this.getNodeLocation(node)
        };
    }
    parseExportDeclaration(node) {
        if (ts.isExportAssignment(node)) {
            return {
                type: 'Export',
                declaration: this.parseExpression(node.expression) || undefined,
                isDefault: !node.isExportEquals,
                location: this.getNodeLocation(node)
            };
        }
        return {
            type: 'Export',
            source: node.moduleSpecifier
                ? node.moduleSpecifier.text
                : undefined,
            location: this.getNodeLocation(node)
        };
    }
    // ========================================================================
    // Helper Methods
    // ========================================================================
    getNodeLocation(node) {
        const start = this.sourceFile.getLineAndCharacterOfPosition(node.getStart(this.sourceFile));
        const end = this.sourceFile.getLineAndCharacterOfPosition(node.getEnd());
        return {
            file: this.filePath,
            startLine: start.line + 1,
            startColumn: start.character,
            endLine: end.line + 1,
            endColumn: end.character
        };
    }
    parseType(node) {
        const name = node.getText(this.sourceFile);
        const isArray = ts.isArrayTypeNode(node);
        const isNullable = ts.isUnionTypeNode(node) &&
            node.types.some(t => t.kind === ts.SyntaxKind.NullKeyword);
        return { name, isArray, isNullable };
    }
    parseModifiers(node) {
        const modifiers = [];
        const nodeModifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
        if (nodeModifiers) {
            for (const mod of nodeModifiers) {
                switch (mod.kind) {
                    case ts.SyntaxKind.PublicKeyword:
                        modifiers.push('public');
                        break;
                    case ts.SyntaxKind.PrivateKeyword:
                        modifiers.push('private');
                        break;
                    case ts.SyntaxKind.ProtectedKeyword:
                        modifiers.push('protected');
                        break;
                    case ts.SyntaxKind.StaticKeyword:
                        modifiers.push('static');
                        break;
                    case ts.SyntaxKind.AbstractKeyword:
                        modifiers.push('abstract');
                        break;
                    case ts.SyntaxKind.ReadonlyKeyword:
                        modifiers.push('readonly');
                        break;
                    case ts.SyntaxKind.AsyncKeyword:
                        modifiers.push('async');
                        break;
                    case ts.SyntaxKind.OverrideKeyword:
                        modifiers.push('override');
                        break;
                }
            }
        }
        return modifiers;
    }
    getVariableKind(list) {
        if (list.flags & ts.NodeFlags.Const) {
            return 'const';
        }
        if (list.flags & ts.NodeFlags.Let) {
            return 'let';
        }
        return 'var';
    }
    parseForInitializer(init) {
        if (ts.isVariableDeclarationList(init)) {
            const decls = [];
            const kind = this.getVariableKind(init);
            for (const decl of init.declarations) {
                decls.push({
                    type: 'VariableDeclaration',
                    name: decl.name.getText(this.sourceFile),
                    initializer: decl.initializer ? this.parseExpression(decl.initializer) || undefined : undefined,
                    kind,
                    location: this.getNodeLocation(decl)
                });
            }
            return decls.length === 1 ? decls[0] : {
                type: 'Block',
                statements: decls,
                location: this.getNodeLocation(init)
            };
        }
        return this.parseExpression(init);
    }
    getBinaryOperator(kind) {
        const operatorMap = {
            [ts.SyntaxKind.PlusToken]: '+',
            [ts.SyntaxKind.MinusToken]: '-',
            [ts.SyntaxKind.AsteriskToken]: '*',
            [ts.SyntaxKind.SlashToken]: '/',
            [ts.SyntaxKind.PercentToken]: '%',
            [ts.SyntaxKind.AsteriskAsteriskToken]: '**',
            [ts.SyntaxKind.EqualsEqualsToken]: '==',
            [ts.SyntaxKind.EqualsEqualsEqualsToken]: '===',
            [ts.SyntaxKind.ExclamationEqualsToken]: '!=',
            [ts.SyntaxKind.ExclamationEqualsEqualsToken]: '!==',
            [ts.SyntaxKind.LessThanToken]: '<',
            [ts.SyntaxKind.LessThanEqualsToken]: '<=',
            [ts.SyntaxKind.GreaterThanToken]: '>',
            [ts.SyntaxKind.GreaterThanEqualsToken]: '>=',
            [ts.SyntaxKind.AmpersandAmpersandToken]: '&&',
            [ts.SyntaxKind.BarBarToken]: '||',
            [ts.SyntaxKind.QuestionQuestionToken]: '??',
            [ts.SyntaxKind.AmpersandToken]: '&',
            [ts.SyntaxKind.BarToken]: '|',
            [ts.SyntaxKind.CaretToken]: '^',
            [ts.SyntaxKind.LessThanLessThanToken]: '<<',
            [ts.SyntaxKind.GreaterThanGreaterThanToken]: '>>',
            [ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken]: '>>>',
            [ts.SyntaxKind.EqualsToken]: '=',
            [ts.SyntaxKind.PlusEqualsToken]: '+=',
            [ts.SyntaxKind.MinusEqualsToken]: '-=',
            [ts.SyntaxKind.AsteriskEqualsToken]: '*=',
            [ts.SyntaxKind.SlashEqualsToken]: '/=',
            [ts.SyntaxKind.PercentEqualsToken]: '%=',
            [ts.SyntaxKind.InKeyword]: 'in',
            [ts.SyntaxKind.InstanceOfKeyword]: 'instanceof'
        };
        return operatorMap[kind] || '?';
    }
    getUnaryOperator(kind) {
        const operatorMap = {
            [ts.SyntaxKind.PlusToken]: '+',
            [ts.SyntaxKind.MinusToken]: '-',
            [ts.SyntaxKind.ExclamationToken]: '!',
            [ts.SyntaxKind.TildeToken]: '~',
            [ts.SyntaxKind.PlusPlusToken]: '++',
            [ts.SyntaxKind.MinusMinusToken]: '--',
            [ts.SyntaxKind.TypeOfKeyword]: 'typeof',
            [ts.SyntaxKind.VoidKeyword]: 'void',
            [ts.SyntaxKind.DeleteKeyword]: 'delete'
        };
        return operatorMap[kind] || '?';
    }
    isAssignmentOperator(kind) {
        return [
            ts.SyntaxKind.EqualsToken,
            ts.SyntaxKind.PlusEqualsToken,
            ts.SyntaxKind.MinusEqualsToken,
            ts.SyntaxKind.AsteriskEqualsToken,
            ts.SyntaxKind.SlashEqualsToken,
            ts.SyntaxKind.PercentEqualsToken,
            ts.SyntaxKind.AmpersandEqualsToken,
            ts.SyntaxKind.BarEqualsToken,
            ts.SyntaxKind.CaretEqualsToken,
            ts.SyntaxKind.LessThanLessThanEqualsToken,
            ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
            ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
            ts.SyntaxKind.AsteriskAsteriskEqualsToken,
            ts.SyntaxKind.QuestionQuestionEqualsToken,
            ts.SyntaxKind.BarBarEqualsToken,
            ts.SyntaxKind.AmpersandAmpersandEqualsToken
        ].includes(kind);
    }
}
exports.TypeScriptParser = TypeScriptParser;
// Factory functions
function createJavaScriptParser() {
    return new TypeScriptParser(false);
}
function createTypeScriptParser() {
    return new TypeScriptParser(true);
}
//# sourceMappingURL=typescriptParser.js.map