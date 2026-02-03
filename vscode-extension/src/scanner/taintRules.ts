/**
 * Taint Analysis Rules - Sources, Sinks, and Sanitizers
 *
 * This module defines the taint sources, sinks, and propagators
 * for multi-language security analysis.
 */

import {
    TaintSource,
    TaintSink,
    TaintPropagator,
    TaintSourceCategory,
    TaintSinkCategory,
    SupportedLanguage,
    VulnerabilityType
} from './types';

// ============================================================================
// Taint Sources by Category
// ============================================================================

export const TAINT_SOURCES: TaintSource[] = [
    // ========== User Input Sources ==========
    // JavaScript/TypeScript - Web
    {
        id: 'js-req-body',
        name: 'HTTP Request Body',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'body' },
        description: 'HTTP request body from Express/Node.js'
    },
    {
        id: 'js-req-query',
        name: 'HTTP Query Parameters',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'query' },
        description: 'HTTP query parameters from Express/Node.js'
    },
    {
        id: 'js-req-params',
        name: 'HTTP Route Parameters',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'params' },
        description: 'HTTP route parameters from Express/Node.js'
    },
    {
        id: 'js-req-headers',
        name: 'HTTP Headers',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'headers' },
        description: 'HTTP headers from request'
    },
    {
        id: 'js-url-search-params',
        name: 'URL Search Parameters',
        category: 'user-input',
        pattern: { type: 'constructor', className: 'URLSearchParams' },
        description: 'URL search parameters'
    },
    {
        id: 'js-form-data',
        name: 'Form Data',
        category: 'user-input',
        pattern: { type: 'constructor', className: 'FormData' },
        description: 'HTML form data'
    },
    {
        id: 'js-document-location',
        name: 'Document Location',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'location' },
        description: 'Browser document location'
    },
    {
        id: 'js-document-referrer',
        name: 'Document Referrer',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'referrer' },
        description: 'Browser document referrer'
    },
    {
        id: 'js-document-cookie',
        name: 'Document Cookie',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'cookie' },
        description: 'Browser cookies'
    },
    {
        id: 'js-local-storage',
        name: 'Local Storage',
        category: 'user-input',
        pattern: { type: 'method-call', methodName: 'getItem', className: 'localStorage' },
        description: 'Browser local storage'
    },

    // Python - Web
    {
        id: 'py-flask-request-form',
        name: 'Flask Request Form',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'form' },
        description: 'Flask request form data'
    },
    {
        id: 'py-flask-request-args',
        name: 'Flask Request Args',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'args' },
        description: 'Flask request arguments'
    },
    {
        id: 'py-flask-request-json',
        name: 'Flask Request JSON',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'json' },
        description: 'Flask request JSON body'
    },
    {
        id: 'py-django-request-get',
        name: 'Django Request GET',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'GET' },
        description: 'Django GET parameters'
    },
    {
        id: 'py-django-request-post',
        name: 'Django Request POST',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'POST' },
        description: 'Django POST parameters'
    },
    {
        id: 'py-input',
        name: 'Python Input',
        category: 'user-input',
        pattern: { type: 'function-call', functionName: 'input' },
        description: 'Python input() function'
    },
    {
        id: 'py-sys-argv',
        name: 'Command Line Arguments',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'argv' },
        description: 'Python sys.argv'
    },

    // Java - Web
    {
        id: 'java-servlet-parameter',
        name: 'Servlet Parameter',
        category: 'user-input',
        pattern: { type: 'method-call', methodName: 'getParameter' },
        description: 'HttpServletRequest.getParameter()'
    },
    {
        id: 'java-servlet-header',
        name: 'Servlet Header',
        category: 'user-input',
        pattern: { type: 'method-call', methodName: 'getHeader' },
        description: 'HttpServletRequest.getHeader()'
    },
    {
        id: 'java-servlet-path-info',
        name: 'Servlet Path Info',
        category: 'user-input',
        pattern: { type: 'method-call', methodName: 'getPathInfo' },
        description: 'HttpServletRequest.getPathInfo()'
    },
    {
        id: 'java-servlet-query-string',
        name: 'Servlet Query String',
        category: 'user-input',
        pattern: { type: 'method-call', methodName: 'getQueryString' },
        description: 'HttpServletRequest.getQueryString()'
    },
    {
        id: 'java-spring-request-param',
        name: 'Spring RequestParam',
        category: 'user-input',
        pattern: { type: 'method-call', methodName: 'getParameter' },
        description: 'Spring @RequestParam value'
    },
    {
        id: 'java-spring-request-body',
        name: 'Spring RequestBody',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'body' },
        description: 'Spring @RequestBody value'
    },

    // C# / .NET
    {
        id: 'cs-request-query',
        name: 'ASP.NET Request Query',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'Query' },
        description: 'ASP.NET HttpRequest.Query'
    },
    {
        id: 'cs-request-form',
        name: 'ASP.NET Request Form',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'Form' },
        description: 'ASP.NET HttpRequest.Form'
    },
    {
        id: 'cs-request-headers',
        name: 'ASP.NET Request Headers',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: 'Headers' },
        description: 'ASP.NET HttpRequest.Headers'
    },

    // PHP
    {
        id: 'php-get',
        name: 'PHP $_GET',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: '_GET' },
        description: 'PHP $_GET superglobal'
    },
    {
        id: 'php-post',
        name: 'PHP $_POST',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: '_POST' },
        description: 'PHP $_POST superglobal'
    },
    {
        id: 'php-request',
        name: 'PHP $_REQUEST',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: '_REQUEST' },
        description: 'PHP $_REQUEST superglobal'
    },
    {
        id: 'php-cookie',
        name: 'PHP $_COOKIE',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: '_COOKIE' },
        description: 'PHP $_COOKIE superglobal'
    },
    {
        id: 'php-server',
        name: 'PHP $_SERVER',
        category: 'user-input',
        pattern: { type: 'property-access', propertyName: '_SERVER' },
        description: 'PHP $_SERVER superglobal'
    },

    // ========== File Read Sources ==========
    {
        id: 'js-fs-read',
        name: 'Node.js File Read',
        category: 'file-read',
        pattern: { type: 'method-call', methodName: 'readFileSync' },
        description: 'Node.js fs.readFileSync()'
    },
    {
        id: 'py-file-read',
        name: 'Python File Read',
        category: 'file-read',
        pattern: { type: 'method-call', methodName: 'read' },
        description: 'Python file.read()'
    },
    {
        id: 'java-file-read',
        name: 'Java File Read',
        category: 'file-read',
        pattern: { type: 'method-call', methodName: 'readAllBytes' },
        description: 'Java Files.readAllBytes()'
    },

    // ========== Database Read Sources ==========
    {
        id: 'generic-db-result',
        name: 'Database Query Result',
        category: 'database-read',
        pattern: { type: 'method-call', methodName: 'fetchall' },
        description: 'Database query result'
    },

    // ========== Environment Sources ==========
    {
        id: 'js-env',
        name: 'Environment Variable',
        category: 'environment',
        pattern: { type: 'property-access', propertyName: 'env' },
        description: 'process.env in Node.js'
    },
    {
        id: 'py-env',
        name: 'Python Environment',
        category: 'environment',
        pattern: { type: 'method-call', methodName: 'getenv' },
        description: 'os.getenv() in Python'
    },
    {
        id: 'java-env',
        name: 'Java Environment',
        category: 'environment',
        pattern: { type: 'method-call', methodName: 'getenv' },
        description: 'System.getenv() in Java'
    }
];

// ============================================================================
// Taint Sinks by Category
// ============================================================================

export const TAINT_SINKS: TaintSink[] = [
    // ========== SQL Injection Sinks ==========
    {
        id: 'js-sql-query',
        name: 'SQL Query Execution',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'query' },
        vulnerabilityType: 'sql-injection',
        description: 'Direct SQL query execution'
    },
    {
        id: 'js-sequelize-raw',
        name: 'Sequelize Raw Query',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'raw' },
        vulnerabilityType: 'sql-injection',
        description: 'Sequelize raw SQL query'
    },
    {
        id: 'py-cursor-execute',
        name: 'Python DB Execute',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'execute' },
        vulnerabilityType: 'sql-injection',
        description: 'Python database cursor.execute()'
    },
    {
        id: 'py-django-raw',
        name: 'Django Raw SQL',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'raw' },
        vulnerabilityType: 'sql-injection',
        description: 'Django Model.objects.raw()'
    },
    {
        id: 'java-statement-execute',
        name: 'Java Statement Execute',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'executeQuery' },
        vulnerabilityType: 'sql-injection',
        description: 'Java Statement.executeQuery()'
    },
    {
        id: 'java-jdbc-template',
        name: 'Spring JdbcTemplate',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'queryForObject' },
        vulnerabilityType: 'sql-injection',
        description: 'Spring JdbcTemplate query'
    },
    {
        id: 'cs-sql-command',
        name: 'C# SqlCommand',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'ExecuteReader' },
        vulnerabilityType: 'sql-injection',
        description: '.NET SqlCommand execution'
    },
    {
        id: 'php-mysql-query',
        name: 'PHP MySQL Query',
        category: 'sql-query',
        pattern: { type: 'function-call', functionName: 'mysql_query' },
        vulnerabilityType: 'sql-injection',
        description: 'PHP mysql_query()'
    },
    {
        id: 'php-mysqli-query',
        name: 'PHP MySQLi Query',
        category: 'sql-query',
        pattern: { type: 'method-call', methodName: 'query' },
        vulnerabilityType: 'sql-injection',
        description: 'PHP mysqli::query()'
    },

    // ========== Command Injection Sinks ==========
    {
        id: 'js-exec',
        name: 'Node.js exec',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'exec' },
        vulnerabilityType: 'command-injection',
        description: 'child_process.exec()'
    },
    {
        id: 'js-exec-sync',
        name: 'Node.js execSync',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'execSync' },
        vulnerabilityType: 'command-injection',
        description: 'child_process.execSync()'
    },
    {
        id: 'js-spawn-shell',
        name: 'Node.js spawn with shell',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'spawn' },
        vulnerabilityType: 'command-injection',
        description: 'child_process.spawn() with shell option'
    },
    {
        id: 'py-os-system',
        name: 'Python os.system',
        category: 'command-execution',
        pattern: { type: 'method-call', methodName: 'system' },
        vulnerabilityType: 'command-injection',
        description: 'os.system()'
    },
    {
        id: 'py-subprocess-shell',
        name: 'Python subprocess shell',
        category: 'command-execution',
        pattern: { type: 'method-call', methodName: 'run' },
        vulnerabilityType: 'command-injection',
        description: 'subprocess.run() with shell=True'
    },
    {
        id: 'py-os-popen',
        name: 'Python os.popen',
        category: 'command-execution',
        pattern: { type: 'method-call', methodName: 'popen' },
        vulnerabilityType: 'command-injection',
        description: 'os.popen()'
    },
    {
        id: 'java-runtime-exec',
        name: 'Java Runtime.exec',
        category: 'command-execution',
        pattern: { type: 'method-call', methodName: 'exec' },
        vulnerabilityType: 'command-injection',
        description: 'Runtime.getRuntime().exec()'
    },
    {
        id: 'java-process-builder',
        name: 'Java ProcessBuilder',
        category: 'command-execution',
        pattern: { type: 'constructor', className: 'ProcessBuilder' },
        vulnerabilityType: 'command-injection',
        description: 'new ProcessBuilder()'
    },
    {
        id: 'cs-process-start',
        name: 'C# Process.Start',
        category: 'command-execution',
        pattern: { type: 'method-call', methodName: 'Start', className: 'Process' },
        vulnerabilityType: 'command-injection',
        description: 'System.Diagnostics.Process.Start()'
    },
    {
        id: 'php-exec',
        name: 'PHP exec',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'exec' },
        vulnerabilityType: 'command-injection',
        description: 'PHP exec()'
    },
    {
        id: 'php-system',
        name: 'PHP system',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'system' },
        vulnerabilityType: 'command-injection',
        description: 'PHP system()'
    },
    {
        id: 'php-shell-exec',
        name: 'PHP shell_exec',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'shell_exec' },
        vulnerabilityType: 'command-injection',
        description: 'PHP shell_exec()'
    },
    {
        id: 'php-passthru',
        name: 'PHP passthru',
        category: 'command-execution',
        pattern: { type: 'function-call', functionName: 'passthru' },
        vulnerabilityType: 'command-injection',
        description: 'PHP passthru()'
    },

    // ========== XSS Sinks ==========
    {
        id: 'js-innerhtml',
        name: 'innerHTML Assignment',
        category: 'html-output',
        pattern: { type: 'property-access', propertyName: 'innerHTML' },
        vulnerabilityType: 'xss',
        description: 'element.innerHTML assignment'
    },
    {
        id: 'js-outerhtml',
        name: 'outerHTML Assignment',
        category: 'html-output',
        pattern: { type: 'property-access', propertyName: 'outerHTML' },
        vulnerabilityType: 'xss',
        description: 'element.outerHTML assignment'
    },
    {
        id: 'js-document-write',
        name: 'document.write',
        category: 'html-output',
        pattern: { type: 'method-call', methodName: 'write' },
        vulnerabilityType: 'xss',
        description: 'document.write()'
    },
    {
        id: 'js-insert-adjacent-html',
        name: 'insertAdjacentHTML',
        category: 'html-output',
        pattern: { type: 'method-call', methodName: 'insertAdjacentHTML' },
        vulnerabilityType: 'xss',
        description: 'element.insertAdjacentHTML()'
    },
    {
        id: 'react-dangerously-set',
        name: 'React dangerouslySetInnerHTML',
        category: 'html-output',
        pattern: { type: 'property-access', propertyName: 'dangerouslySetInnerHTML' },
        vulnerabilityType: 'xss',
        description: 'React dangerouslySetInnerHTML'
    },
    {
        id: 'vue-v-html',
        name: 'Vue v-html',
        category: 'html-output',
        pattern: { type: 'property-access', propertyName: 'v-html' },
        vulnerabilityType: 'xss',
        description: 'Vue v-html directive'
    },
    {
        id: 'angular-innerhtml',
        name: 'Angular [innerHTML]',
        category: 'html-output',
        pattern: { type: 'property-access', propertyName: '[innerHTML]' },
        vulnerabilityType: 'xss',
        description: 'Angular [innerHTML] binding'
    },
    {
        id: 'py-render-template-string',
        name: 'Flask render_template_string',
        category: 'html-output',
        pattern: { type: 'function-call', functionName: 'render_template_string' },
        vulnerabilityType: 'xss',
        description: 'Flask render_template_string()'
    },
    {
        id: 'py-mark-safe',
        name: 'Django mark_safe',
        category: 'html-output',
        pattern: { type: 'function-call', functionName: 'mark_safe' },
        vulnerabilityType: 'xss',
        description: 'Django mark_safe()'
    },
    {
        id: 'php-echo',
        name: 'PHP echo',
        category: 'html-output',
        pattern: { type: 'function-call', functionName: 'echo' },
        vulnerabilityType: 'xss',
        description: 'PHP echo'
    },
    {
        id: 'php-print',
        name: 'PHP print',
        category: 'html-output',
        pattern: { type: 'function-call', functionName: 'print' },
        vulnerabilityType: 'xss',
        description: 'PHP print'
    },

    // ========== Path Traversal Sinks ==========
    {
        id: 'js-fs-operations',
        name: 'Node.js File Operations',
        category: 'file-operation',
        pattern: { type: 'method-call', methodName: 'readFile' },
        vulnerabilityType: 'path-traversal',
        description: 'fs.readFile() and related'
    },
    {
        id: 'py-open',
        name: 'Python open',
        category: 'file-operation',
        pattern: { type: 'function-call', functionName: 'open' },
        vulnerabilityType: 'path-traversal',
        description: 'Python open()'
    },
    {
        id: 'java-file-new',
        name: 'Java File Constructor',
        category: 'file-operation',
        pattern: { type: 'constructor', className: 'File' },
        vulnerabilityType: 'path-traversal',
        description: 'new File()'
    },
    {
        id: 'php-fopen',
        name: 'PHP fopen',
        category: 'file-operation',
        pattern: { type: 'function-call', functionName: 'fopen' },
        vulnerabilityType: 'path-traversal',
        description: 'PHP fopen()'
    },
    {
        id: 'php-file-get-contents',
        name: 'PHP file_get_contents',
        category: 'file-operation',
        pattern: { type: 'function-call', functionName: 'file_get_contents' },
        vulnerabilityType: 'path-traversal',
        description: 'PHP file_get_contents()'
    },
    {
        id: 'php-include',
        name: 'PHP include/require',
        category: 'file-operation',
        pattern: { type: 'function-call', functionName: 'include' },
        vulnerabilityType: 'path-traversal',
        description: 'PHP include()/require()'
    },

    // ========== Code Injection Sinks ==========
    {
        id: 'js-eval',
        name: 'JavaScript eval',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'eval' },
        vulnerabilityType: 'code-injection',
        description: 'eval()'
    },
    {
        id: 'js-function-constructor',
        name: 'JavaScript Function Constructor',
        category: 'code-execution',
        pattern: { type: 'constructor', className: 'Function' },
        vulnerabilityType: 'code-injection',
        description: 'new Function()'
    },
    {
        id: 'js-settimeout-string',
        name: 'setTimeout with string',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'setTimeout' },
        vulnerabilityType: 'code-injection',
        description: 'setTimeout() with string argument'
    },
    {
        id: 'py-eval',
        name: 'Python eval',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'eval' },
        vulnerabilityType: 'code-injection',
        description: 'Python eval()'
    },
    {
        id: 'py-exec',
        name: 'Python exec',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'exec' },
        vulnerabilityType: 'code-injection',
        description: 'Python exec()'
    },
    {
        id: 'php-eval',
        name: 'PHP eval',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'eval' },
        vulnerabilityType: 'code-injection',
        description: 'PHP eval()'
    },
    {
        id: 'php-create-function',
        name: 'PHP create_function',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'create_function' },
        vulnerabilityType: 'code-injection',
        description: 'PHP create_function()'
    },
    {
        id: 'php-preg-replace-e',
        name: 'PHP preg_replace /e',
        category: 'code-execution',
        pattern: { type: 'function-call', functionName: 'preg_replace' },
        vulnerabilityType: 'code-injection',
        description: 'PHP preg_replace() with /e modifier'
    },

    // ========== Deserialization Sinks ==========
    {
        id: 'py-pickle-load',
        name: 'Python pickle.load',
        category: 'deserialization',
        pattern: { type: 'method-call', methodName: 'loads' },
        vulnerabilityType: 'deserialization',
        description: 'pickle.loads()'
    },
    {
        id: 'py-yaml-load',
        name: 'Python yaml.load',
        category: 'deserialization',
        pattern: { type: 'method-call', methodName: 'load' },
        vulnerabilityType: 'deserialization',
        description: 'yaml.load() without SafeLoader'
    },
    {
        id: 'java-object-input-stream',
        name: 'Java ObjectInputStream',
        category: 'deserialization',
        pattern: { type: 'method-call', methodName: 'readObject' },
        vulnerabilityType: 'deserialization',
        description: 'ObjectInputStream.readObject()'
    },
    {
        id: 'php-unserialize',
        name: 'PHP unserialize',
        category: 'deserialization',
        pattern: { type: 'function-call', functionName: 'unserialize' },
        vulnerabilityType: 'deserialization',
        description: 'PHP unserialize()'
    },
    {
        id: 'cs-binary-formatter',
        name: 'C# BinaryFormatter',
        category: 'deserialization',
        pattern: { type: 'method-call', methodName: 'Deserialize' },
        vulnerabilityType: 'deserialization',
        description: 'BinaryFormatter.Deserialize()'
    },

    // ========== SSRF Sinks ==========
    {
        id: 'js-fetch',
        name: 'JavaScript fetch',
        category: 'url-redirect',
        pattern: { type: 'function-call', functionName: 'fetch' },
        vulnerabilityType: 'ssrf',
        description: 'fetch() with user-controlled URL'
    },
    {
        id: 'js-axios-get',
        name: 'Axios GET',
        category: 'url-redirect',
        pattern: { type: 'method-call', methodName: 'get' },
        vulnerabilityType: 'ssrf',
        description: 'axios.get() with user-controlled URL'
    },
    {
        id: 'py-requests-get',
        name: 'Python requests.get',
        category: 'url-redirect',
        pattern: { type: 'method-call', methodName: 'get' },
        vulnerabilityType: 'ssrf',
        description: 'requests.get() with user-controlled URL'
    },
    {
        id: 'py-urllib',
        name: 'Python urllib',
        category: 'url-redirect',
        pattern: { type: 'method-call', methodName: 'urlopen' },
        vulnerabilityType: 'ssrf',
        description: 'urllib.request.urlopen()'
    },
    {
        id: 'java-url-open-connection',
        name: 'Java URL Connection',
        category: 'url-redirect',
        pattern: { type: 'method-call', methodName: 'openConnection' },
        vulnerabilityType: 'ssrf',
        description: 'URL.openConnection()'
    },
    {
        id: 'php-curl',
        name: 'PHP cURL',
        category: 'url-redirect',
        pattern: { type: 'function-call', functionName: 'curl_exec' },
        vulnerabilityType: 'ssrf',
        description: 'PHP curl_exec()'
    },
    {
        id: 'php-file-get-contents-url',
        name: 'PHP file_get_contents URL',
        category: 'url-redirect',
        pattern: { type: 'function-call', functionName: 'file_get_contents' },
        vulnerabilityType: 'ssrf',
        description: 'PHP file_get_contents() with URL'
    },

    // ========== Open Redirect Sinks ==========
    {
        id: 'js-window-location',
        name: 'JavaScript window.location',
        category: 'url-redirect',
        pattern: { type: 'property-access', propertyName: 'location' },
        vulnerabilityType: 'open-redirect',
        description: 'window.location assignment'
    },
    {
        id: 'js-location-href',
        name: 'JavaScript location.href',
        category: 'url-redirect',
        pattern: { type: 'property-access', propertyName: 'href' },
        vulnerabilityType: 'open-redirect',
        description: 'location.href assignment'
    },
    {
        id: 'py-flask-redirect',
        name: 'Flask redirect',
        category: 'url-redirect',
        pattern: { type: 'function-call', functionName: 'redirect' },
        vulnerabilityType: 'open-redirect',
        description: 'Flask redirect()'
    },
    {
        id: 'java-sendredirect',
        name: 'Java sendRedirect',
        category: 'url-redirect',
        pattern: { type: 'method-call', methodName: 'sendRedirect' },
        vulnerabilityType: 'open-redirect',
        description: 'HttpServletResponse.sendRedirect()'
    },
    {
        id: 'php-header-location',
        name: 'PHP header Location',
        category: 'url-redirect',
        pattern: { type: 'function-call', functionName: 'header' },
        vulnerabilityType: 'open-redirect',
        description: 'PHP header("Location: ...")'
    },

    // ========== XXE Sinks ==========
    {
        id: 'js-xml-parse',
        name: 'JavaScript XML Parse',
        category: 'xml-parse',
        pattern: { type: 'method-call', methodName: 'parseFromString' },
        vulnerabilityType: 'xxe',
        description: 'DOMParser.parseFromString()'
    },
    {
        id: 'py-xml-parse',
        name: 'Python XML Parse',
        category: 'xml-parse',
        pattern: { type: 'function-call', functionName: 'parse' },
        vulnerabilityType: 'xxe',
        description: 'xml.etree.ElementTree.parse()'
    },
    {
        id: 'java-document-builder',
        name: 'Java DocumentBuilder',
        category: 'xml-parse',
        pattern: { type: 'method-call', methodName: 'parse' },
        vulnerabilityType: 'xxe',
        description: 'DocumentBuilder.parse()'
    },
    {
        id: 'php-simplexml',
        name: 'PHP SimpleXML',
        category: 'xml-parse',
        pattern: { type: 'function-call', functionName: 'simplexml_load_string' },
        vulnerabilityType: 'xxe',
        description: 'PHP simplexml_load_string()'
    },

    // ========== LDAP Injection Sinks ==========
    {
        id: 'java-ldap-search',
        name: 'Java LDAP Search',
        category: 'ldap-query',
        pattern: { type: 'method-call', methodName: 'search' },
        vulnerabilityType: 'ldap-injection',
        description: 'DirContext.search()'
    },
    {
        id: 'py-ldap-search',
        name: 'Python LDAP Search',
        category: 'ldap-query',
        pattern: { type: 'method-call', methodName: 'search_s' },
        vulnerabilityType: 'ldap-injection',
        description: 'ldap.search_s()'
    }
];

// ============================================================================
// Taint Sanitizers/Propagators
// ============================================================================

export const TAINT_PROPAGATORS: TaintPropagator[] = [
    // ========== Sanitizers ==========
    // JavaScript
    {
        id: 'js-encode-uri',
        name: 'encodeURIComponent',
        pattern: { type: 'function-call', functionName: 'encodeURIComponent' },
        propagationType: 'sanitizer'
    },
    {
        id: 'js-encode-uri-full',
        name: 'encodeURI',
        pattern: { type: 'function-call', functionName: 'encodeURI' },
        propagationType: 'sanitizer'
    },
    {
        id: 'js-dompurify',
        name: 'DOMPurify.sanitize',
        pattern: { type: 'method-call', methodName: 'sanitize', className: 'DOMPurify' },
        propagationType: 'sanitizer'
    },
    {
        id: 'js-escape-html',
        name: 'escapeHtml',
        pattern: { type: 'function-call', functionName: 'escapeHtml' },
        propagationType: 'sanitizer'
    },
    {
        id: 'js-validator-escape',
        name: 'validator.escape',
        pattern: { type: 'method-call', methodName: 'escape' },
        propagationType: 'sanitizer'
    },

    // Python
    {
        id: 'py-html-escape',
        name: 'html.escape',
        pattern: { type: 'method-call', methodName: 'escape' },
        propagationType: 'sanitizer'
    },
    {
        id: 'py-markupsafe-escape',
        name: 'markupsafe.escape',
        pattern: { type: 'function-call', functionName: 'escape' },
        propagationType: 'sanitizer'
    },
    {
        id: 'py-quote',
        name: 'urllib.parse.quote',
        pattern: { type: 'function-call', functionName: 'quote' },
        propagationType: 'sanitizer'
    },
    {
        id: 'py-bleach-clean',
        name: 'bleach.clean',
        pattern: { type: 'method-call', methodName: 'clean' },
        propagationType: 'sanitizer'
    },

    // Java
    {
        id: 'java-owasp-encoder',
        name: 'OWASP Encoder',
        pattern: { type: 'method-call', methodName: 'forHtml', className: 'Encode' },
        propagationType: 'sanitizer'
    },
    {
        id: 'java-string-utils-escape',
        name: 'StringEscapeUtils',
        pattern: { type: 'method-call', methodName: 'escapeHtml4' },
        propagationType: 'sanitizer'
    },
    {
        id: 'java-prepared-statement',
        name: 'PreparedStatement',
        pattern: { type: 'method-call', methodName: 'setString' },
        propagationType: 'sanitizer'
    },

    // PHP
    {
        id: 'php-htmlspecialchars',
        name: 'htmlspecialchars',
        pattern: { type: 'function-call', functionName: 'htmlspecialchars' },
        propagationType: 'sanitizer'
    },
    {
        id: 'php-htmlentities',
        name: 'htmlentities',
        pattern: { type: 'function-call', functionName: 'htmlentities' },
        propagationType: 'sanitizer'
    },
    {
        id: 'php-mysqli-escape',
        name: 'mysqli_real_escape_string',
        pattern: { type: 'function-call', functionName: 'mysqli_real_escape_string' },
        propagationType: 'sanitizer'
    },
    {
        id: 'php-pdo-quote',
        name: 'PDO::quote',
        pattern: { type: 'method-call', methodName: 'quote' },
        propagationType: 'sanitizer'
    },
    {
        id: 'php-prepared-statement',
        name: 'PDO Prepared Statement',
        pattern: { type: 'method-call', methodName: 'prepare' },
        propagationType: 'sanitizer'
    },

    // C#
    {
        id: 'cs-html-encode',
        name: 'HtmlEncoder.Encode',
        pattern: { type: 'method-call', methodName: 'Encode', className: 'HtmlEncoder' },
        propagationType: 'sanitizer'
    },
    {
        id: 'cs-sql-parameter',
        name: 'SqlParameter',
        pattern: { type: 'constructor', className: 'SqlParameter' },
        propagationType: 'sanitizer'
    },

    // ========== Passthrough Propagators ==========
    {
        id: 'string-concat',
        name: 'String Concatenation',
        pattern: { type: 'method-call', methodName: 'concat' },
        propagationType: 'passthrough'
    },
    {
        id: 'string-substring',
        name: 'String Substring',
        pattern: { type: 'method-call', methodName: 'substring' },
        propagationType: 'passthrough'
    },
    {
        id: 'string-replace',
        name: 'String Replace',
        pattern: { type: 'method-call', methodName: 'replace' },
        propagationType: 'passthrough'
    },
    {
        id: 'string-trim',
        name: 'String Trim',
        pattern: { type: 'method-call', methodName: 'trim' },
        propagationType: 'passthrough'
    },
    {
        id: 'string-tolower',
        name: 'String toLowerCase',
        pattern: { type: 'method-call', methodName: 'toLowerCase' },
        propagationType: 'passthrough'
    },
    {
        id: 'string-toupper',
        name: 'String toUpperCase',
        pattern: { type: 'method-call', methodName: 'toUpperCase' },
        propagationType: 'passthrough'
    },
    {
        id: 'array-join',
        name: 'Array Join',
        pattern: { type: 'method-call', methodName: 'join' },
        propagationType: 'passthrough'
    },
    {
        id: 'json-stringify',
        name: 'JSON Stringify',
        pattern: { type: 'method-call', methodName: 'stringify' },
        propagationType: 'passthrough'
    },
    {
        id: 'json-parse',
        name: 'JSON Parse',
        pattern: { type: 'method-call', methodName: 'parse' },
        propagationType: 'passthrough'
    },

    // ========== Transformers ==========
    {
        id: 'base64-encode',
        name: 'Base64 Encode',
        pattern: { type: 'method-call', methodName: 'btoa' },
        propagationType: 'transformer'
    },
    {
        id: 'base64-decode',
        name: 'Base64 Decode',
        pattern: { type: 'method-call', methodName: 'atob' },
        propagationType: 'transformer'
    }
];

// ============================================================================
// Helper Functions
// ============================================================================

export function getSourcesByCategory(category: TaintSourceCategory): TaintSource[] {
    return TAINT_SOURCES.filter(s => s.category === category);
}

export function getSinksByCategory(category: TaintSinkCategory): TaintSink[] {
    return TAINT_SINKS.filter(s => s.category === category);
}

export function getSinksByVulnerabilityType(vulnType: VulnerabilityType): TaintSink[] {
    return TAINT_SINKS.filter(s => s.vulnerabilityType === vulnType);
}

export function getSanitizers(): TaintPropagator[] {
    return TAINT_PROPAGATORS.filter(p => p.propagationType === 'sanitizer');
}

export function getSourcesForLanguage(language: SupportedLanguage): TaintSource[] {
    const languagePatterns: Record<SupportedLanguage, string[]> = {
        'javascript': ['js-', 'generic-'],
        'typescript': ['js-', 'generic-'],
        'python': ['py-', 'generic-'],
        'java': ['java-', 'generic-'],
        'csharp': ['cs-', 'generic-'],
        'php': ['php-', 'generic-'],
        'kotlin': ['java-', 'kotlin-', 'generic-'],
        'objectivec': ['objc-', 'generic-'],
        'swift': ['swift-', 'generic-'],
        'go': ['go-', 'generic-'],
        'ruby': ['ruby-', 'generic-']
    };

    const prefixes = languagePatterns[language] || ['generic-'];
    return TAINT_SOURCES.filter(s => prefixes.some(p => s.id.startsWith(p)));
}

export function getSinksForLanguage(language: SupportedLanguage): TaintSink[] {
    const languagePatterns: Record<SupportedLanguage, string[]> = {
        'javascript': ['js-', 'react-', 'vue-', 'angular-', 'generic-'],
        'typescript': ['js-', 'react-', 'vue-', 'angular-', 'generic-'],
        'python': ['py-', 'generic-'],
        'java': ['java-', 'generic-'],
        'csharp': ['cs-', 'generic-'],
        'php': ['php-', 'generic-'],
        'kotlin': ['java-', 'kotlin-', 'generic-'],
        'objectivec': ['objc-', 'generic-'],
        'swift': ['swift-', 'generic-'],
        'go': ['go-', 'generic-'],
        'ruby': ['ruby-', 'generic-']
    };

    const prefixes = languagePatterns[language] || ['generic-'];
    return TAINT_SINKS.filter(s => prefixes.some(p => s.id.startsWith(p)));
}
