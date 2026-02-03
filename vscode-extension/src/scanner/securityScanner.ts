/**
 * Enhanced Security Scanner
 *
 * Main entry point for the AST-based security scanner.
 * Coordinates parsing, analysis, and finding generation.
 */

import {
    SupportedLanguage,
    ProgramNode,
    ControlFlowGraph,
    DataFlowGraph,
    AnalysisResult,
    SecurityFinding,
    Severity,
    Confidence,
    VulnerabilityType,
    FunctionNode,
    MethodNode,
    Scope,
    CodeMetrics,
    TaintFlow,
    TaintSource,
    TaintSink,
    TaintSinkCategory,
    TaintPathNode,
    TaintedValue,
    SourceLocation,
    IRNode
} from './types';

import { ParserRegistry, BaseParser } from './parsers/baseParser';
import { TypeScriptParser, createJavaScriptParser, createTypeScriptParser } from './parsers/typescriptParser';
import { createPythonParser } from './parsers/pythonParser';
import { createJavaParser } from './parsers/javaParser';
import { createGoParser } from './parsers/goParser';
import { CFGBuilder, CFGAnalyzer } from './analysis/cfgBuilder';
import { DFGBuilder, DFGAnalyzer } from './analysis/dfgBuilder';
import { TaintAnalyzer, TaintAnalysisUtils } from './analysis/taintAnalyzer';

export interface ScanOptions {
    enableTaintAnalysis?: boolean;
    enableCFGAnalysis?: boolean;
    enableDFGAnalysis?: boolean;
    enablePatternMatching?: boolean;
    maxFileSize?: number;
    timeout?: number;
}

const DEFAULT_OPTIONS: ScanOptions = {
    enableTaintAnalysis: true,
    enableCFGAnalysis: true,
    enableDFGAnalysis: true,
    enablePatternMatching: true,
    maxFileSize: 1000000, // 1MB
    timeout: 30000 // 30 seconds
};

export class SecurityScanner {
    private parserRegistry: ParserRegistry;
    private options: ScanOptions;

    constructor(options: Partial<ScanOptions> = {}) {
        this.options = { ...DEFAULT_OPTIONS, ...options };
        this.parserRegistry = new ParserRegistry();

        // Register parsers
        this.registerParsers();
    }

    private registerParsers(): void {
        // JavaScript/TypeScript
        this.parserRegistry.register(createJavaScriptParser());
        this.parserRegistry.register(createTypeScriptParser());

        // Python
        this.parserRegistry.register(createPythonParser());

        // Java
        this.parserRegistry.register(createJavaParser());

        // Go
        this.parserRegistry.register(createGoParser());
    }

    /**
     * Scan a single file and return analysis results
     */
    async scanFile(source: string, filePath: string): Promise<AnalysisResult | null> {
        const startTime = Date.now();
        console.log('[SecurityScanner] Starting scan for:', filePath);
        console.log('[SecurityScanner] Source length:', source.length);

        // Check file size
        if (source.length > this.options.maxFileSize!) {
            console.warn(`File ${filePath} exceeds maximum size, skipping`);
            return null;
        }

        // Get appropriate parser
        const parser = this.parserRegistry.getParserForFile(filePath);
        console.log('[SecurityScanner] Parser found:', !!parser);
        if (!parser) {
            console.warn(`No parser available for ${filePath}`);
            return null;
        }

        const language = this.parserRegistry.getLanguageForFile(filePath)!;
        console.log('[SecurityScanner] Language:', language);

        try {
            // Phase 1: Parse to IR
            console.log('[SecurityScanner] Starting parse...');
            const program = await parser.parse(source, filePath);
            console.log('[SecurityScanner] Parse complete, body length:', program?.body?.length);
            const symbolTable = parser.buildSymbolTable(program);

            // Phase 2: Build CFGs for all functions
            const cfgMap = new Map<string, ControlFlowGraph>();
            if (this.options.enableCFGAnalysis) {
                this.buildCFGs(program, cfgMap);
            }

            // Phase 3: Build DFG
            let dfg: DataFlowGraph = {
                nodes: new Map(),
                defUseChains: new Map(),
                useDefChains: new Map()
            };

            if (this.options.enableDFGAnalysis && cfgMap.size > 0) {
                const dfgBuilder = new DFGBuilder();
                // Build DFG from the first function's CFG (simplified)
                // In production, you'd merge DFGs or handle interprocedurally
                const firstCfg = cfgMap.values().next().value;
                if (firstCfg) {
                    dfg = dfgBuilder.build(firstCfg, symbolTable);
                }
            }

            // Phase 4: Taint Analysis
            const taintFlows: TaintFlow[] = [];
            if (this.options.enableTaintAnalysis) {
                const taintAnalyzer = new TaintAnalyzer(language);
                taintFlows.push(...taintAnalyzer.analyze(program, cfgMap, dfg));
            }

            // Phase 5: Pattern Matching (for hardcoded secrets, weak crypto, etc.)
            const patternFindings: SecurityFinding[] = [];
            if (this.options.enablePatternMatching) {
                console.log('[SecurityScanner] Running pattern analysis...');
                patternFindings.push(...this.runPatternAnalysis(program, source, filePath));
                console.log('[SecurityScanner] Pattern findings:', patternFindings.length);
            }

            // Phase 6: Generate Security Findings
            console.log('[SecurityScanner] Generating findings from taint flows:', taintFlows.length);
            const findings = this.generateFindings(taintFlows, patternFindings, source, filePath);
            console.log('[SecurityScanner] Total findings:', findings.length);

            // Calculate metrics
            const metrics = this.calculateMetrics(program, cfgMap);

            const analysisTime = Date.now() - startTime;
            console.log('[SecurityScanner] Scan complete in', analysisTime, 'ms');

            return {
                file: filePath,
                language,
                program,
                symbolTable,
                cfg: cfgMap,
                dfg,
                findings,
                metrics,
                analysisTime
            };

        } catch (error: any) {
            console.error(`[SecurityScanner] Error scanning ${filePath}:`, error?.message || error);
            console.error('[SecurityScanner] Stack:', error?.stack);
            return null;
        }
    }

    /**
     * Scan multiple files
     */
    async scanFiles(files: Array<{ path: string; content: string }>): Promise<AnalysisResult[]> {
        const results: AnalysisResult[] = [];

        for (const file of files) {
            const result = await this.scanFile(file.content, file.path);
            if (result) {
                results.push(result);
            }
        }

        return results;
    }

    // ========================================================================
    // CFG Building
    // ========================================================================

    private buildCFGs(program: ProgramNode, cfgMap: Map<string, ControlFlowGraph>): void {
        const cfgBuilder = new CFGBuilder();

        const processNode = (node: any) => {
            if (node.type === 'Function' || node.type === 'Method') {
                const func = node as FunctionNode | MethodNode;
                const cfg = cfgBuilder.build(func);
                cfgMap.set(func.name, cfg);
            } else if (node.type === 'Class') {
                for (const member of node.members) {
                    if (member.type === 'Method' || member.type === 'Constructor') {
                        const cfg = cfgBuilder.build(member);
                        const name = member.type === 'Constructor'
                            ? `${node.name}.constructor`
                            : `${node.name}.${member.name}`;
                        cfgMap.set(name, cfg);
                    }
                }
            }
        };

        for (const node of program.body) {
            processNode(node);
        }
    }

    // ========================================================================
    // Pattern Analysis - Comprehensive vulnerability detection matching webapp
    // ========================================================================

    private runPatternAnalysis(
        program: ProgramNode,
        source: string,
        filePath: string
    ): SecurityFinding[] {
        const findings: SecurityFinding[] = [];

        // ==================== SQL INJECTION PATTERNS ====================
        const sqlInjectionPatterns = [
            {
                pattern: /(execute|query|exec|executemany|rawQuery)\s*\(\s*["'].*?(\+|%|\$\{|f["'])/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - String Concatenation',
                severity: 'critical' as Severity
            },
            {
                pattern: /(cursor|db|conn)\.(execute|query)\s*\([^)]*\+/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - Database Query',
                severity: 'critical' as Severity
            },
            {
                pattern: /(SELECT|INSERT|UPDATE|DELETE).*?(\+|%s|\$\{)/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - Direct Query Construction',
                severity: 'critical' as Severity
            },
            {
                pattern: /createQuery\s*\([^)]*\+/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - JPA Query',
                severity: 'critical' as Severity
            },
            {
                pattern: /f["'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER).*?\{/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - Python f-string',
                severity: 'critical' as Severity
            },
            {
                pattern: /f["'].*?WHERE.*?\{/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - f-string WHERE clause',
                severity: 'critical' as Severity
            },
            {
                pattern: /`.*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?\$\{/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - Template Literal',
                severity: 'critical' as Severity
            },
            {
                pattern: /["'].*?(SELECT|INSERT|UPDATE|DELETE).*?["']\.format\s*\(/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - String Format',
                severity: 'critical' as Severity
            },
            {
                pattern: /raw\s*\([^)]*\+/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'SQL Injection - Raw Query',
                severity: 'critical' as Severity
            }
        ];

        // ==================== NOSQL INJECTION PATTERNS ====================
        const nosqlInjectionPatterns = [
            {
                pattern: /(find|findOne|update|remove)\s*\(\s*\{.*?(\$|request\.|params\.)/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'NoSQL Injection',
                severity: 'high' as Severity
            },
            {
                pattern: /db\.collection.*?\$where/gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'NoSQL Injection - $where Operator',
                severity: 'high' as Severity
            },
            {
                pattern: /new\s+ObjectId\s*\([^)]*req\./gi,
                type: 'sql-injection' as VulnerabilityType,
                title: 'NoSQL Injection - ObjectId',
                severity: 'high' as Severity
            }
        ];

        // ==================== XSS PATTERNS ====================
        const xssPatterns = [
            {
                pattern: /(innerHTML|outerHTML)\s*=\s*[^;]+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - innerHTML/outerHTML Assignment',
                severity: 'high' as Severity
            },
            {
                pattern: /document\.write\s*\([^)]+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - document.write',
                severity: 'high' as Severity
            },
            {
                pattern: /dangerouslySetInnerHTML\s*=/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - React dangerouslySetInnerHTML',
                severity: 'high' as Severity
            },
            {
                pattern: /\.html\s*\([^)]*(\+|\$\{|`)/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - jQuery .html()',
                severity: 'high' as Severity
            },
            {
                pattern: /\.html\s*\(\s*\w+\s*\)/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - jQuery .html() with variable',
                severity: 'high' as Severity
            },
            {
                pattern: /\.(append|prepend|after|before|replaceWith)\s*\(\s*["']?</gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - jQuery DOM Manipulation',
                severity: 'high' as Severity
            },
            {
                pattern: /\$\s*\([^)]*<[^>]+>/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - jQuery HTML Selector',
                severity: 'high' as Severity
            },
            {
                pattern: /(eval|Function)\s*\(.*?(request\.|params\.|req\.|args\.|query\.)/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - eval/Function with User Input',
                severity: 'critical' as Severity
            },
            {
                pattern: /(eval|Function)\s*\(\s*\w+\s*\)/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - eval/Function with Variable',
                severity: 'high' as Severity
            },
            {
                pattern: /location\s*=\s*[^;]+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - Location Assignment',
                severity: 'medium' as Severity
            },
            {
                pattern: /location\.href\s*=\s*[^;]+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - location.href Assignment',
                severity: 'medium' as Severity
            },
            {
                pattern: /window\.open\s*\([^)]*\+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - window.open with Concatenation',
                severity: 'medium' as Severity
            },
            {
                pattern: /setAttribute\s*\([^,]*,\s*[^)]+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - setAttribute',
                severity: 'medium' as Severity
            },
            {
                pattern: /render_template_string\s*\(/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - Flask render_template_string',
                severity: 'critical' as Severity
            },
            {
                pattern: /Markup\s*\([^)]*\+/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - Markup Concatenation',
                severity: 'high' as Severity
            },
            {
                pattern: /\{%.*?autoescape\s+false/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - Autoescape Disabled',
                severity: 'high' as Severity
            },
            {
                pattern: /\{\{.*?\|safe\}\}/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - Template Safe Filter',
                severity: 'medium' as Severity
            },
            {
                pattern: /echo\s+\$/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - PHP Echo Variable',
                severity: 'high' as Severity
            },
            {
                pattern: /print\s+\$/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - PHP Print Variable',
                severity: 'high' as Severity
            },
            {
                pattern: /<\?=\s*\$/gi,
                type: 'xss' as VulnerabilityType,
                title: 'XSS - PHP Short Echo',
                severity: 'high' as Severity
            }
        ];

        // ==================== COMMAND INJECTION PATTERNS ====================
        const commandInjectionPatterns = [
            {
                pattern: /(exec|system|popen|shell_exec|passthru|proc_open)\s*\(.*?(\+|f["']|\$\{)/gi,
                type: 'command-injection' as VulnerabilityType,
                title: 'Command Injection - Shell Execution',
                severity: 'critical' as Severity
            },
            {
                pattern: /subprocess\.(call|run|Popen).*?shell\s*=\s*True/gi,
                type: 'command-injection' as VulnerabilityType,
                title: 'Command Injection - subprocess with shell=True',
                severity: 'critical' as Severity
            },
            {
                pattern: /os\.(system|popen|exec).*?(\+|f["'])/gi,
                type: 'command-injection' as VulnerabilityType,
                title: 'Command Injection - os.system/popen',
                severity: 'critical' as Severity
            },
            {
                pattern: /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/gi,
                type: 'command-injection' as VulnerabilityType,
                title: 'Command Injection - Java Runtime.exec',
                severity: 'critical' as Severity
            },
            {
                pattern: /cmd\s*\/c.*?(\+|\$)/gi,
                type: 'command-injection' as VulnerabilityType,
                title: 'Command Injection - Windows cmd',
                severity: 'critical' as Severity
            }
        ];

        // ==================== HARDCODED CREDENTIALS PATTERNS ====================
        const secretPatterns = [
            {
                pattern: /(password|passwd|pwd|secret|api[_-]?key|token|auth)\s*=\s*["'][^"']{6,}["']/gi,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'Hardcoded Password/Secret',
                severity: 'critical' as Severity
            },
            {
                pattern: /(DB_PASSWORD|DATABASE_PASSWORD|SECRET_KEY)\s*=\s*["'][^"']{6,}["']/gi,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'Hardcoded Database Password',
                severity: 'critical' as Severity
            },
            {
                pattern: /(AWS_SECRET|PRIVATE_KEY|CLIENT_SECRET)\s*=\s*["'][^"']{8,}["']/gi,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'Hardcoded AWS/Private Key',
                severity: 'critical' as Severity
            },
            {
                pattern: /AKIA[A-Z0-9]{16}/g,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'AWS Access Key ID',
                severity: 'critical' as Severity
            },
            {
                pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'Private Key in Code',
                severity: 'critical' as Severity
            },
            {
                pattern: /ghp_[a-zA-Z0-9]{36}/g,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'GitHub Personal Access Token',
                severity: 'critical' as Severity
            }
        ];

        // ==================== WEAK CRYPTO PATTERNS ====================
        const cryptoPatterns = [
            {
                pattern: /(md5|sha1|DES|RC4|RC2)\s*\(/gi,
                type: 'weak-crypto' as VulnerabilityType,
                title: 'Weak Cryptographic Algorithm',
                severity: 'high' as Severity
            },
            {
                pattern: /(MD5|SHA1)DigestUtils/gi,
                type: 'weak-crypto' as VulnerabilityType,
                title: 'Weak Hash - DigestUtils',
                severity: 'high' as Severity
            },
            {
                pattern: /Cipher\.getInstance\s*\(["']DES/gi,
                type: 'weak-crypto' as VulnerabilityType,
                title: 'Weak Cipher - DES',
                severity: 'high' as Severity
            },
            {
                pattern: /crypto\.createCipheriv\s*\(["']des/gi,
                type: 'weak-crypto' as VulnerabilityType,
                title: 'Weak Cipher - Node.js DES',
                severity: 'high' as Severity
            },
            {
                pattern: /(key|secret|iv|salt)\s*=\s*b?["'][^"']{16,}["']/gi,
                type: 'hardcoded-secret' as VulnerabilityType,
                title: 'Hardcoded Cryptographic Key',
                severity: 'critical' as Severity
            },
            {
                pattern: /random\.(random|randint|choice)/gi,
                type: 'insecure-random' as VulnerabilityType,
                title: 'Insecure Random - Python random module',
                severity: 'medium' as Severity
            },
            {
                pattern: /Math\.random\s*\(\)/g,
                type: 'insecure-random' as VulnerabilityType,
                title: 'Insecure Random - Math.random',
                severity: 'medium' as Severity
            },
            {
                pattern: /new Random\s*\(/gi,
                type: 'insecure-random' as VulnerabilityType,
                title: 'Insecure Random - Java Random',
                severity: 'medium' as Severity
            }
        ];

        // ==================== INSECURE JWT PATTERNS ====================
        const jwtPatterns = [
            {
                pattern: /jwt\.encode.*?algorithm\s*=\s*["']none["']/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Insecure JWT - None Algorithm',
                severity: 'critical' as Severity
            },
            {
                pattern: /jwt\.decode.*?verify\s*=\s*False/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Insecure JWT - Verification Disabled',
                severity: 'critical' as Severity
            },
            {
                pattern: /jsonwebtoken\.sign\(\s*[^,]*,\s*["']["']/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Insecure JWT - Empty Secret',
                severity: 'critical' as Severity
            }
        ];

        // ==================== INSECURE DESERIALIZATION PATTERNS ====================
        const deserializationPatterns = [
            {
                pattern: /pickle\.(loads|load)\s*\(/gi,
                type: 'deserialization' as VulnerabilityType,
                title: 'Insecure Deserialization - pickle',
                severity: 'critical' as Severity
            },
            {
                pattern: /yaml\.load\s*\([^)]*(?!Loader)/gi,
                type: 'deserialization' as VulnerabilityType,
                title: 'Insecure Deserialization - yaml.load',
                severity: 'critical' as Severity
            },
            {
                pattern: /\beval\s*\(/g,
                type: 'code-injection' as VulnerabilityType,
                title: 'Code Injection - eval()',
                severity: 'high' as Severity
            },
            {
                pattern: /\bexec\s*\(/g,
                type: 'code-injection' as VulnerabilityType,
                title: 'Code Injection - exec()',
                severity: 'high' as Severity
            },
            {
                pattern: /(ObjectInputStream|readObject)\s*\(/gi,
                type: 'deserialization' as VulnerabilityType,
                title: 'Insecure Deserialization - Java ObjectInputStream',
                severity: 'critical' as Severity
            },
            {
                pattern: /unserialize\s*\(/gi,
                type: 'deserialization' as VulnerabilityType,
                title: 'Insecure Deserialization - PHP unserialize',
                severity: 'critical' as Severity
            }
        ];

        // ==================== PATH TRAVERSAL PATTERNS ====================
        const pathTraversalPatterns = [
            {
                pattern: /(open|read|readFile|file_get_contents)\s*\([^)]*(\+|f["']|\$\{)/gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - File Operation',
                severity: 'high' as Severity
            },
            {
                pattern: /(File|FileInputStream|FileReader)\s*\([^)]*\+/gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - Java File Operation',
                severity: 'high' as Severity
            },
            {
                pattern: /\.\.\//g,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - Directory Traversal Sequence',
                severity: 'high' as Severity
            },
            {
                pattern: /open\s*\(\s*f["']/gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - open with f-string',
                severity: 'high' as Severity
            },
            {
                pattern: /fs\.(readFile|writeFile|readFileSync|writeFileSync|readdir|unlink)\s*\([^)]*\+/gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - Node.js fs Operation',
                severity: 'high' as Severity
            },
            {
                pattern: /path\.join\s*\([^)]*req\./gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - path.join with request',
                severity: 'high' as Severity
            },
            {
                pattern: /path\.resolve\s*\([^)]*req\./gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - path.resolve with request',
                severity: 'high' as Severity
            },
            {
                pattern: /(include|require|include_once|require_once)\s*\([^)]*\$/gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - PHP include/require',
                severity: 'critical' as Severity
            },
            {
                pattern: /extractall\s*\(/gi,
                type: 'path-traversal' as VulnerabilityType,
                title: 'Path Traversal - Zip Slip (extractall)',
                severity: 'high' as Severity
            }
        ];

        // ==================== SSRF PATTERNS ====================
        const ssrfPatterns = [
            {
                pattern: /requests\.(get|post|put|delete|head|options)\s*\([^)]*\+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - Python requests with concatenation',
                severity: 'high' as Severity
            },
            {
                pattern: /requests\.(get|post|put|delete)\s*\(\s*f["']/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - Python requests with f-string',
                severity: 'high' as Severity
            },
            {
                pattern: /requests\.(get|post|put|delete)\s*\(\s*\w+\s*[,)]/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - Python requests with variable',
                severity: 'high' as Severity
            },
            {
                pattern: /urllib\.request\.urlopen\s*\([^)]*\+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - urllib urlopen',
                severity: 'high' as Severity
            },
            {
                pattern: /fetch\s*\(\s*\w+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - fetch with variable',
                severity: 'high' as Severity
            },
            {
                pattern: /fetch\s*\([^)]*\+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - fetch with concatenation',
                severity: 'high' as Severity
            },
            {
                pattern: /axios\.(get|post|put|delete)\s*\([^)]*\+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - axios with concatenation',
                severity: 'high' as Severity
            },
            {
                pattern: /axios\.(get|post|put|delete)\s*\(\s*\w+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - axios with variable',
                severity: 'high' as Severity
            },
            {
                pattern: /new\s+URL\s*\([^)]*\+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - Java URL with concatenation',
                severity: 'high' as Severity
            },
            {
                pattern: /http\.Get\s*\([^)]*\+/gi,
                type: 'ssrf' as VulnerabilityType,
                title: 'SSRF - Go http.Get',
                severity: 'high' as Severity
            }
        ];

        // ==================== OPEN REDIRECT PATTERNS ====================
        const openRedirectPatterns = [
            {
                pattern: /redirect\s*\(\s*request\./gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - redirect with request',
                severity: 'medium' as Severity
            },
            {
                pattern: /redirect\s*\([^)]*\+/gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - redirect with concatenation',
                severity: 'medium' as Severity
            },
            {
                pattern: /HttpResponseRedirect\s*\([^)]*\+/gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - Django HttpResponseRedirect',
                severity: 'medium' as Severity
            },
            {
                pattern: /res\.redirect\s*\([^)]*\+/gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - Express redirect',
                severity: 'medium' as Severity
            },
            {
                pattern: /res\.redirect\s*\(\s*req\./gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - Express redirect with req',
                severity: 'medium' as Severity
            },
            {
                pattern: /sendRedirect\s*\([^)]*\+/gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - Java sendRedirect',
                severity: 'medium' as Severity
            },
            {
                pattern: /header\s*\([^)]*Location[^)]*\$/gi,
                type: 'open-redirect' as VulnerabilityType,
                title: 'Open Redirect - PHP header Location',
                severity: 'medium' as Severity
            }
        ];

        // ==================== SSTI PATTERNS ====================
        const sstiPatterns = [
            {
                pattern: /render_template_string\s*\([^)]*\+/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - render_template_string with concatenation',
                severity: 'critical' as Severity
            },
            {
                pattern: /render_template_string\s*\(\s*\w+/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - render_template_string with variable',
                severity: 'critical' as Severity
            },
            {
                pattern: /Template\s*\([^)]*\+/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - Template with concatenation',
                severity: 'critical' as Severity
            },
            {
                pattern: /Template\s*\(\s*\w+\s*\)/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - Template with variable',
                severity: 'critical' as Severity
            },
            {
                pattern: /ejs\.render\s*\([^)]*,\s*\{/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - EJS render',
                severity: 'high' as Severity
            },
            {
                pattern: /pug\.render\s*\([^)]*\+/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - Pug render',
                severity: 'high' as Severity
            },
            {
                pattern: /handlebars\.compile\s*\([^)]*\+/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - Handlebars compile',
                severity: 'high' as Severity
            },
            {
                pattern: /nunjucks\.renderString\s*\([^)]*\+/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'SSTI - Nunjucks renderString',
                severity: 'high' as Severity
            }
        ];

        // ==================== XXE PATTERNS ====================
        const xxePatterns = [
            {
                pattern: /xml\.etree\.ElementTree\.parse\s*\(/gi,
                type: 'xxe' as VulnerabilityType,
                title: 'XXE - Python ElementTree parse',
                severity: 'high' as Severity
            },
            {
                pattern: /lxml\.etree\.parse\s*\(/gi,
                type: 'xxe' as VulnerabilityType,
                title: 'XXE - lxml parse',
                severity: 'high' as Severity
            },
            {
                pattern: /DocumentBuilderFactory\.newInstance\s*\(/gi,
                type: 'xxe' as VulnerabilityType,
                title: 'XXE - Java DocumentBuilderFactory',
                severity: 'high' as Severity
            },
            {
                pattern: /SAXParserFactory\.newInstance\s*\(/gi,
                type: 'xxe' as VulnerabilityType,
                title: 'XXE - Java SAXParserFactory',
                severity: 'high' as Severity
            },
            {
                pattern: /XMLInputFactory\.newInstance\s*\(/gi,
                type: 'xxe' as VulnerabilityType,
                title: 'XXE - Java XMLInputFactory',
                severity: 'high' as Severity
            },
            {
                pattern: /simplexml_load_string\s*\(/gi,
                type: 'xxe' as VulnerabilityType,
                title: 'XXE - PHP simplexml_load_string',
                severity: 'high' as Severity
            }
        ];

        // ==================== PROTOTYPE POLLUTION PATTERNS ====================
        const prototypePollutionPatterns = [
            {
                pattern: /Object\.assign\s*\([^)]*,\s*\w+\s*\)/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'Prototype Pollution - Object.assign',
                severity: 'high' as Severity
            },
            {
                pattern: /_\.(merge|extend|defaultsDeep)\s*\(/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'Prototype Pollution - Lodash merge/extend',
                severity: 'high' as Severity
            },
            {
                pattern: /\[["']?__proto__["']?\]/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'Prototype Pollution - __proto__ access',
                severity: 'high' as Severity
            },
            {
                pattern: /__proto__\s*:/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'Prototype Pollution - __proto__ assignment',
                severity: 'high' as Severity
            },
            {
                pattern: /constructor\[.*?prototype/gi,
                type: 'code-injection' as VulnerabilityType,
                title: 'Prototype Pollution - constructor.prototype',
                severity: 'high' as Severity
            }
        ];

        // ==================== SECURITY MISCONFIGURATION PATTERNS ====================
        const configPatterns = [
            {
                pattern: /(DEBUG|debug)\s*=\s*True/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Debug Mode Enabled',
                severity: 'high' as Severity
            },
            {
                pattern: /app\.debug\s*=\s*True/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Flask Debug Mode Enabled',
                severity: 'high' as Severity
            },
            {
                pattern: /Access-Control-Allow-Origin.*?\*/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'CORS Misconfiguration - Wildcard Origin',
                severity: 'medium' as Severity
            },
            {
                pattern: /cors\s*\(\s*\{\s*origin\s*:\s*["' ]\*/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'CORS Misconfiguration - Express cors wildcard',
                severity: 'medium' as Severity
            },
            {
                pattern: /verify\s*=\s*False/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'SSL Verification Disabled',
                severity: 'high' as Severity
            },
            {
                pattern: /VERIFY_SSL\s*=\s*False/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'SSL Verification Disabled',
                severity: 'high' as Severity
            },
            {
                pattern: /ssl\._create_unverified_context/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'SSL Unverified Context',
                severity: 'high' as Severity
            }
        ];

        // ==================== INPUT VALIDATION PATTERNS ====================
        const inputValidationPatterns = [
            {
                pattern: /request\.(GET|POST|args|form|json|query|body|params)\[/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Direct User Input Access',
                severity: 'medium' as Severity
            },
            {
                pattern: /req\.(query|params|body)\./gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Express Direct User Input',
                severity: 'medium' as Severity
            },
            {
                pattern: /\$_(GET|POST|REQUEST|COOKIE)\[/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'PHP Direct Superglobal Access',
                severity: 'medium' as Severity
            }
        ];

        // ==================== ACCESS CONTROL PATTERNS ====================
        const accessControlPatterns = [
            {
                pattern: /User\.objects\.get\s*\(\s*id\s*=\s*request\./gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'IDOR - Django User.objects.get',
                severity: 'high' as Severity
            },
            {
                pattern: /findById\s*\(\s*req\.(params|query|body)/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'IDOR - findById with request params',
                severity: 'high' as Severity
            },
            {
                pattern: /user\.role\s*=\s*(request|req)\./gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Privilege Escalation - Role Assignment',
                severity: 'critical' as Severity
            },
            {
                pattern: /user\.is_admin\s*=\s*(True|true|1)/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Privilege Escalation - Admin Assignment',
                severity: 'critical' as Severity
            }
        ];

        // ==================== EXCEPTION HANDLING PATTERNS ====================
        const exceptionPatterns = [
            {
                pattern: /except\s*:\s*\n\s+pass/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Empty Exception Handler',
                severity: 'high' as Severity
            },
            {
                pattern: /catch\s*\([^)]*\)\s*\{\s*\}/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Empty Catch Block',
                severity: 'high' as Severity
            },
            {
                pattern: /except.*?:\s*\n.*?return\s+True/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Fail-Open Exception - Returns True',
                severity: 'critical' as Severity
            },
            {
                pattern: /traceback\.print_exc\s*\(\)/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Verbose Error - Traceback Exposure',
                severity: 'medium' as Severity
            },
            {
                pattern: /console\.error\s*\(\s*\w+\.stack/gi,
                type: 'broken-access-control' as VulnerabilityType,
                title: 'Verbose Error - Stack Exposure',
                severity: 'medium' as Severity
            }
        ];

        // ==================== DANGEROUS FUNCTION PATTERNS ====================
        const dangerousFunctionPatterns = [
            {
                pattern: /new\s+Function\s*\(/g,
                type: 'code-injection' as VulnerabilityType,
                title: 'Dynamic Function Constructor',
                severity: 'high' as Severity
            }
        ];

        const allPatterns = [
            ...sqlInjectionPatterns,
            ...nosqlInjectionPatterns,
            ...xssPatterns,
            ...commandInjectionPatterns,
            ...secretPatterns,
            ...cryptoPatterns,
            ...jwtPatterns,
            ...deserializationPatterns,
            ...pathTraversalPatterns,
            ...ssrfPatterns,
            ...openRedirectPatterns,
            ...sstiPatterns,
            ...xxePatterns,
            ...prototypePollutionPatterns,
            ...configPatterns,
            ...inputValidationPatterns,
            ...accessControlPatterns,
            ...exceptionPatterns,
            ...dangerousFunctionPatterns
        ];

        const lines = source.split('\n');

        for (const patternDef of allPatterns) {
            let match;
            while ((match = patternDef.pattern.exec(source)) !== null) {
                const lineNumber = this.getLineNumber(source, match.index);
                const line = lines[lineNumber - 1] || '';
                const column = match.index - source.lastIndexOf('\n', match.index - 1) - 1;

                const location = {
                    file: filePath,
                    startLine: lineNumber,
                    startColumn: column,
                    endLine: lineNumber,
                    endColumn: column + match[0].length
                };

                const codeSnippet = line.trim();

                findings.push({
                    id: `pattern_${findings.length + 1}`,
                    type: patternDef.type,
                    severity: patternDef.severity,
                    title: patternDef.title,
                    description: `Detected ${patternDef.title} at line ${lineNumber}`,
                    location,
                    cweId: TaintAnalysisUtils.getCWEForVulnerability(patternDef.type),
                    owaspCategory: TaintAnalysisUtils.getOWASPCategory(patternDef.type),
                    codeSnippet,
                    recommendation: this.getRecommendation(patternDef.type),
                    confidence: 'high',
                    // Add fix code for AI fix feature
                    fix: {
                        code: this.getFixCode(patternDef.type, codeSnippet, filePath),
                        description: this.getRecommendation(patternDef.type)
                    },
                    // Add simulated taint flow for visualization
                    taintFlow: this.generateTaintFlow(patternDef.type, location, codeSnippet)
                });
            }
        }

        return findings;
    }

    private getLineNumber(source: string, index: number): number {
        return source.substring(0, index).split('\n').length;
    }

    private getRecommendation(vulnType: VulnerabilityType): string {
        const recommendations: Record<string, string> = {
            'hardcoded-secret': 'Use environment variables or a secrets management system (AWS Secrets Manager, HashiCorp Vault) to store sensitive values.',
            'weak-crypto': 'Use strong, modern cryptographic algorithms: AES-256-GCM for encryption, SHA-256/SHA-512 for hashing, bcrypt/argon2 for passwords.',
            'insecure-random': 'Use cryptographically secure random number generators: crypto.getRandomValues() (JS), secrets module (Python), SecureRandom (Java).',
            'code-injection': 'Avoid dynamic code execution (eval, exec, Function constructor). Use safer alternatives like JSON.parse() for data parsing.',
            'xss': 'Sanitize user input with DOMPurify before rendering. Use textContent instead of innerHTML. Enable Content-Security-Policy headers.',
            'sql-injection': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Use ORM frameworks.',
            'command-injection': 'Avoid shell execution. Use subprocess with argument lists (shell=False). Validate and whitelist inputs.',
            'path-traversal': 'Validate file paths with os.path.basename(). Use path.resolve() and verify paths are within allowed directories. Reject paths with ".." sequences.',
            'ssrf': 'Validate and whitelist allowed URLs/domains. Block private IP ranges (10.x, 172.16-31.x, 192.168.x) and localhost.',
            'xxe': 'Disable external entity processing in XML parsers. Use defusedxml in Python, set secure features in Java DocumentBuilderFactory.',
            'deserialization': 'Avoid deserializing untrusted data. Use safe formats like JSON. For YAML, use yaml.safe_load(). Never use pickle with untrusted data.',
            'open-redirect': 'Validate redirect URLs against a whitelist of allowed destinations. Use relative URLs when possible.',
            'broken-access-control': 'Implement proper authentication and authorization checks. Disable debug mode in production. Use secure CORS configuration.',
            'ldap-injection': 'Use parameterized LDAP queries. Escape special characters with ldap3.utils.conv.escape_filter_chars().',
            'nosql-injection': 'Validate and sanitize all user inputs. Avoid using $where operators. Use query builders.',
            'ssti': 'Never pass user input directly to template engines. Use pre-defined templates with placeholders. Enable strict sandboxing.',
            'prototype-pollution': 'Sanitize object keys. Use Object.create(null) for safe objects. Reject __proto__, constructor, and prototype keys.',
            'idor': 'Always verify resource ownership. Use indirect references. Implement proper authorization decorators.',
            'jwt-vulnerability': 'Use strong secrets (256+ bits), explicit algorithms (RS256, HS256), and short expiration times. Never use "none" algorithm.'
        };

        return recommendations[vulnType] || 'Review and fix the security issue.';
    }

    /**
     * Generate fix code for a given vulnerability type and code snippet
     */
    public getFixCode(vulnType: VulnerabilityType, codeSnippet: string, filePath: string): string {
        const ext = filePath.substring(filePath.lastIndexOf('.'));
        const isJS = ['.js', '.jsx', '.ts', '.tsx'].includes(ext);
        const isPython = ext === '.py';
        const isJava = ext === '.java';

        const fixes: Record<string, () => string> = {
            'sql-injection': () => {
                if (isPython) {
                    return `# Use parameterized queries instead of string concatenation
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`;
                } else if (isJS) {
                    return `// Use parameterized queries
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);`;
                } else if (isJava) {
                    return `// Use PreparedStatement with parameterized queries
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();`;
                }
                return `// Use parameterized queries instead of string concatenation`;
            },
            'xss': () => {
                if (isJS) {
                    return `// Use textContent or sanitize with DOMPurify
import DOMPurify from 'dompurify';
element.textContent = userInput; // Safe: auto-escaped
// OR
element.innerHTML = DOMPurify.sanitize(userInput); // Sanitized HTML`;
                }
                return `// Sanitize user input before rendering to prevent XSS`;
            },
            'command-injection': () => {
                if (isPython) {
                    return `# Use subprocess with shell=False and argument list
import subprocess
subprocess.run(['ls', '-la', filename], shell=False, check=True)`;
                } else if (isJS) {
                    return `// Use execFile with argument array instead of exec
const { execFile } = require('child_process');
execFile('ls', ['-la', filename], (error, stdout) => {});`;
                }
                return `// Avoid shell execution, use argument lists`;
            },
            'path-traversal': () => {
                if (isPython) {
                    return `# Validate and sanitize file paths
import os
base_dir = '/safe/directory'
requested_path = os.path.join(base_dir, os.path.basename(user_input))
if not requested_path.startswith(base_dir):
    raise ValueError('Invalid path')`;
                } else if (isJS) {
                    return `// Validate file paths
const path = require('path');
const safePath = path.join(baseDir, path.basename(userInput));
if (!safePath.startsWith(baseDir)) throw new Error('Invalid path');`;
                }
                return `// Validate and sanitize file paths`;
            },
            'hardcoded-secret': () => {
                if (isPython) {
                    return `# Use environment variables for secrets
import os
API_KEY = os.environ.get('API_KEY')
# Or use a secrets manager`;
                } else if (isJS) {
                    return `// Use environment variables for secrets
const API_KEY = process.env.API_KEY;
// Or use a secrets manager like AWS Secrets Manager`;
                }
                return `// Store secrets in environment variables or a secrets manager`;
            },
            'weak-crypto': () => {
                if (isPython) {
                    return `# Use strong cryptographic algorithms
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
# For hashing
digest = hashes.Hash(hashes.SHA256())
# For encryption
key = Fernet.generate_key()
fernet = Fernet(key)`;
                } else if (isJS) {
                    return `// Use strong cryptographic algorithms
const crypto = require('crypto');
// For hashing
const hash = crypto.createHash('sha256').update(data).digest('hex');
// For encryption
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`;
                }
                return `// Use strong cryptographic algorithms (SHA-256, AES-256-GCM)`;
            },
            'code-injection': () => {
                if (isJS) {
                    return `// Avoid eval() - use safer alternatives
// Instead of: eval(userInput)
// Use JSON.parse() for JSON data:
const data = JSON.parse(userInput);
// Or use a sandboxed environment for code execution`;
                } else if (isPython) {
                    return `# Avoid exec/eval - use safer alternatives
# Instead of: exec(user_input)
# Use ast.literal_eval for safe literal parsing:
import ast
data = ast.literal_eval(user_input)`;
                }
                return `// Avoid dynamic code execution`;
            },
            'ssrf': () => {
                if (isJS) {
                    return `// Validate URLs and block private IP ranges
const url = new URL(userUrl);
const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0'];
if (blockedHosts.includes(url.hostname) ||
    url.hostname.startsWith('192.168.') ||
    url.hostname.startsWith('10.') ||
    url.hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)) {
    throw new Error('Access to internal URLs is forbidden');
}`;
                }
                return `// Validate and whitelist allowed URLs`;
            },
            'xxe': () => {
                if (isPython) {
                    return `# Use defusedxml to prevent XXE
from defusedxml import ElementTree
tree = ElementTree.parse(xml_file)`;
                } else if (isJava) {
                    return `// Disable external entities in XML parser
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);`;
                }
                return `// Disable external entity processing in XML parsers`;
            },
            'deserialization': () => {
                if (isPython) {
                    return `# Use safe deserialization
import json
# Instead of pickle.loads(untrusted_data)
data = json.loads(untrusted_data)
# For YAML, use safe_load:
import yaml
data = yaml.safe_load(yaml_string)`;
                } else if (isJS) {
                    return `// Use JSON for safe deserialization
const data = JSON.parse(untrustedInput);
// Avoid deserializing with eval or Function`;
                }
                return `// Use safe deserialization methods`;
            },
            'insecure-random': () => {
                if (isJS) {
                    return `// Use cryptographically secure random
const crypto = require('crypto');
const secureRandom = crypto.randomBytes(32).toString('hex');
// Or in browser:
const array = new Uint32Array(1);
crypto.getRandomValues(array);`;
                } else if (isPython) {
                    return `# Use secrets module for cryptographic randomness
import secrets
secure_token = secrets.token_hex(32)
secure_number = secrets.randbelow(100)`;
                }
                return `// Use cryptographically secure random number generators`;
            }
        };

        const fixGenerator = fixes[vulnType];
        return fixGenerator ? fixGenerator() : this.getRecommendation(vulnType);
    }

    /**
     * Generate simulated taint flow for pattern-based findings
     */
    private generateTaintFlow(
        vulnType: VulnerabilityType,
        location: SourceLocation,
        codeSnippet: string
    ): TaintFlow {
        // Create a dummy IRNode for the path nodes
        const dummyNode: IRNode = {
            type: 'Identifier',
            location: location
        } as IRNode;

        const sourceNode: IRNode = {
            type: 'Identifier',
            location: {
                file: location.file,
                startLine: Math.max(1, location.startLine - 2),
                startColumn: 0,
                endLine: Math.max(1, location.startLine - 2),
                endColumn: 50
            }
        } as IRNode;

        const propagatorNode: IRNode = {
            type: 'Identifier',
            location: {
                file: location.file,
                startLine: Math.max(1, location.startLine - 1),
                startColumn: 0,
                endLine: Math.max(1, location.startLine - 1),
                endColumn: 50
            }
        } as IRNode;

        const source: TaintSource = {
            id: `source_${Date.now()}`,
            name: 'User Input',
            category: 'user-input',
            pattern: { type: 'function-call', functionName: 'input' },
            description: 'Data from user input or external source'
        };

        const sink: TaintSink = {
            id: `sink_${Date.now()}`,
            name: this.getSinkName(vulnType),
            category: this.getSinkCategory(vulnType),
            pattern: { type: 'function-call', functionName: vulnType },
            vulnerabilityType: vulnType,
            description: `Security-sensitive operation: ${vulnType}`
        };

        const path: TaintPathNode[] = [
            {
                location: sourceNode.location,
                description: 'Tainted data enters from user input',
                node: sourceNode
            },
            {
                location: propagatorNode.location,
                description: 'Data flows through variable assignment',
                node: propagatorNode
            },
            {
                location: location,
                description: `Tainted data reaches ${vulnType} sink: ${codeSnippet.substring(0, 50)}`,
                node: dummyNode
            }
        ];

        const taintedValue: TaintedValue = {
            variable: 'userInput',
            source: source,
            location: sourceNode.location,
            path: path
        };

        return {
            source,
            sink,
            taintedValue,
            path,
            sanitizers: []
        };
    }

    private getSinkName(vulnType: VulnerabilityType): string {
        const sinkNames: Record<string, string> = {
            'sql-injection': 'Database Query',
            'xss': 'DOM Manipulation',
            'command-injection': 'Shell Execution',
            'path-traversal': 'File System Access',
            'ssrf': 'HTTP Request',
            'xxe': 'XML Parser',
            'code-injection': 'Code Evaluation',
            'deserialization': 'Deserialization',
            'ldap-injection': 'LDAP Query',
            'ssti': 'Template Rendering'
        };
        return sinkNames[vulnType] || 'Security-Sensitive Operation';
    }

    private getSinkCategory(vulnType: VulnerabilityType): TaintSinkCategory {
        const categories: Record<string, TaintSinkCategory> = {
            'sql-injection': 'sql-query',
            'xss': 'html-output',
            'command-injection': 'command-execution',
            'path-traversal': 'file-operation',
            'ssrf': 'url-redirect',
            'xxe': 'deserialization',
            'code-injection': 'code-execution',
            'deserialization': 'deserialization',
            'ldap-injection': 'ldap-query',
            'ssti': 'html-output'
        };
        return categories[vulnType] || 'code-execution';
    }

    // ========================================================================
    // Finding Generation
    // ========================================================================

    private generateFindings(
        taintFlows: TaintFlow[],
        patternFindings: SecurityFinding[],
        source: string,
        filePath: string
    ): SecurityFinding[] {
        const findings: SecurityFinding[] = [...patternFindings];
        const lines = source.split('\n');

        // Convert taint flows to findings
        for (const flow of taintFlows) {
            const location = flow.path[flow.path.length - 1].location;
            const lineContent = lines[location.startLine - 1] || '';

            findings.push({
                id: `taint_${findings.length + 1}`,
                type: flow.sink.vulnerabilityType,
                severity: TaintAnalysisUtils.getSeverityForVulnerability(flow.sink.vulnerabilityType),
                title: `${flow.sink.vulnerabilityType.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} Vulnerability`,
                description: TaintAnalysisUtils.describeTaintFlow(flow),
                location,
                cweId: TaintAnalysisUtils.getCWEForVulnerability(flow.sink.vulnerabilityType),
                owaspCategory: TaintAnalysisUtils.getOWASPCategory(flow.sink.vulnerabilityType),
                taintFlow: flow,
                codeSnippet: lineContent.trim(),
                recommendation: this.getRecommendation(flow.sink.vulnerabilityType),
                confidence: flow.sanitizers.length > 0 ? 'medium' : 'high'
            });
        }

        // Sort by severity
        const severityOrder: Record<Severity, number> = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3,
            info: 4
        };

        findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        return findings;
    }

    // ========================================================================
    // Metrics Calculation
    // ========================================================================

    private calculateMetrics(
        program: ProgramNode,
        cfgMap: Map<string, ControlFlowGraph>
    ): CodeMetrics {
        let linesOfCode = 0;
        let numberOfFunctions = 0;
        let numberOfClasses = 0;
        let totalComplexity = 0;
        let maxNestingDepth = 0;

        // Count functions and classes
        for (const node of program.body) {
            if (node.type === 'Function') {
                numberOfFunctions++;
            } else if (node.type === 'Class') {
                numberOfClasses++;
                const classNode = node as any;
                numberOfFunctions += classNode.members.filter((m: any) =>
                    m.type === 'Method' || m.type === 'Constructor'
                ).length;
            }
        }

        // Calculate cyclomatic complexity from CFGs
        for (const cfg of cfgMap.values()) {
            totalComplexity += CFGAnalyzer.getCyclomaticComplexity(cfg);
        }

        // Estimate lines of code
        if (program.body.length > 0) {
            const first = program.body[0].location;
            const last = program.body[program.body.length - 1].location;
            linesOfCode = last.endLine - first.startLine + 1;
        }

        return {
            linesOfCode,
            cyclomaticComplexity: totalComplexity,
            numberOfFunctions,
            numberOfClasses,
            maxNestingDepth
        };
    }
}

// ============================================================================
// Factory Function
// ============================================================================

export function createSecurityScanner(options?: Partial<ScanOptions>): SecurityScanner {
    return new SecurityScanner(options);
}
