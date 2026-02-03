/**
 * Enhanced Security Scanner Module
 *
 * Exports the main scanner components for use in the VS Code extension.
 */

// Core types
export * from './types';

// Parser infrastructure
export { BaseParser, ParserRegistry } from './parsers/baseParser';
export {
    TypeScriptParser,
    createJavaScriptParser,
    createTypeScriptParser
} from './parsers/typescriptParser';

// Analysis engines
export { CFGBuilder, CFGAnalyzer } from './analysis/cfgBuilder';
export { DFGBuilder, DFGAnalyzer } from './analysis/dfgBuilder';
export { TaintAnalyzer, TaintAnalysisUtils } from './analysis/taintAnalyzer';

// Taint rules
export {
    TAINT_SOURCES,
    TAINT_SINKS,
    TAINT_PROPAGATORS,
    getSourcesForLanguage,
    getSinksForLanguage,
    getSourcesByCategory,
    getSinksByCategory,
    getSinksByVulnerabilityType,
    getSanitizers
} from './taintRules';

// Main scanner
export {
    SecurityScanner,
    createSecurityScanner,
    ScanOptions
} from './securityScanner';
