"use strict";
/**
 * Enhanced Security Scanner Module
 *
 * Exports the main scanner components for use in the VS Code extension.
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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSecurityScanner = exports.SecurityScanner = exports.getSanitizers = exports.getSinksByVulnerabilityType = exports.getSinksByCategory = exports.getSourcesByCategory = exports.getSinksForLanguage = exports.getSourcesForLanguage = exports.TAINT_PROPAGATORS = exports.TAINT_SINKS = exports.TAINT_SOURCES = exports.TaintAnalysisUtils = exports.TaintAnalyzer = exports.DFGAnalyzer = exports.DFGBuilder = exports.CFGAnalyzer = exports.CFGBuilder = exports.createTypeScriptParser = exports.createJavaScriptParser = exports.TypeScriptParser = exports.ParserRegistry = exports.BaseParser = void 0;
// Core types
__exportStar(require("./types"), exports);
// Parser infrastructure
var baseParser_1 = require("./parsers/baseParser");
Object.defineProperty(exports, "BaseParser", { enumerable: true, get: function () { return baseParser_1.BaseParser; } });
Object.defineProperty(exports, "ParserRegistry", { enumerable: true, get: function () { return baseParser_1.ParserRegistry; } });
var typescriptParser_1 = require("./parsers/typescriptParser");
Object.defineProperty(exports, "TypeScriptParser", { enumerable: true, get: function () { return typescriptParser_1.TypeScriptParser; } });
Object.defineProperty(exports, "createJavaScriptParser", { enumerable: true, get: function () { return typescriptParser_1.createJavaScriptParser; } });
Object.defineProperty(exports, "createTypeScriptParser", { enumerable: true, get: function () { return typescriptParser_1.createTypeScriptParser; } });
// Analysis engines
var cfgBuilder_1 = require("./analysis/cfgBuilder");
Object.defineProperty(exports, "CFGBuilder", { enumerable: true, get: function () { return cfgBuilder_1.CFGBuilder; } });
Object.defineProperty(exports, "CFGAnalyzer", { enumerable: true, get: function () { return cfgBuilder_1.CFGAnalyzer; } });
var dfgBuilder_1 = require("./analysis/dfgBuilder");
Object.defineProperty(exports, "DFGBuilder", { enumerable: true, get: function () { return dfgBuilder_1.DFGBuilder; } });
Object.defineProperty(exports, "DFGAnalyzer", { enumerable: true, get: function () { return dfgBuilder_1.DFGAnalyzer; } });
var taintAnalyzer_1 = require("./analysis/taintAnalyzer");
Object.defineProperty(exports, "TaintAnalyzer", { enumerable: true, get: function () { return taintAnalyzer_1.TaintAnalyzer; } });
Object.defineProperty(exports, "TaintAnalysisUtils", { enumerable: true, get: function () { return taintAnalyzer_1.TaintAnalysisUtils; } });
// Taint rules
var taintRules_1 = require("./taintRules");
Object.defineProperty(exports, "TAINT_SOURCES", { enumerable: true, get: function () { return taintRules_1.TAINT_SOURCES; } });
Object.defineProperty(exports, "TAINT_SINKS", { enumerable: true, get: function () { return taintRules_1.TAINT_SINKS; } });
Object.defineProperty(exports, "TAINT_PROPAGATORS", { enumerable: true, get: function () { return taintRules_1.TAINT_PROPAGATORS; } });
Object.defineProperty(exports, "getSourcesForLanguage", { enumerable: true, get: function () { return taintRules_1.getSourcesForLanguage; } });
Object.defineProperty(exports, "getSinksForLanguage", { enumerable: true, get: function () { return taintRules_1.getSinksForLanguage; } });
Object.defineProperty(exports, "getSourcesByCategory", { enumerable: true, get: function () { return taintRules_1.getSourcesByCategory; } });
Object.defineProperty(exports, "getSinksByCategory", { enumerable: true, get: function () { return taintRules_1.getSinksByCategory; } });
Object.defineProperty(exports, "getSinksByVulnerabilityType", { enumerable: true, get: function () { return taintRules_1.getSinksByVulnerabilityType; } });
Object.defineProperty(exports, "getSanitizers", { enumerable: true, get: function () { return taintRules_1.getSanitizers; } });
// Main scanner
var securityScanner_1 = require("./securityScanner");
Object.defineProperty(exports, "SecurityScanner", { enumerable: true, get: function () { return securityScanner_1.SecurityScanner; } });
Object.defineProperty(exports, "createSecurityScanner", { enumerable: true, get: function () { return securityScanner_1.createSecurityScanner; } });
//# sourceMappingURL=index.js.map