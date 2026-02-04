"use strict";
/**
 * Taint Flow Visualization Panel - Premium SVG Edition
 *
 * High-quality, precision SVG-based flow diagrams showing how tainted data flows
 * from sources to sinks with professional visualization, zoom/pan, code preview,
 * and variable tracking.
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
exports.TaintFlowPanel = void 0;
const vscode = __importStar(require("vscode"));
class TaintFlowPanel {
    constructor(panel, _extensionUri) {
        this._disposables = [];
        this._findings = [];
        this._panel = panel;
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._panel.webview.onDidReceiveMessage(message => this._handleMessage(message), null, this._disposables);
    }
    static show(findings, extensionUri) {
        const column = vscode.ViewColumn.Beside;
        if (TaintFlowPanel.currentPanel) {
            TaintFlowPanel.currentPanel._panel.reveal(column);
            TaintFlowPanel.currentPanel._updateFindings(findings);
            return TaintFlowPanel.currentPanel;
        }
        const panel = vscode.window.createWebviewPanel('taintFlowVisualization', 'Taint Flow Analysis', column, {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [extensionUri]
        });
        TaintFlowPanel.currentPanel = new TaintFlowPanel(panel, extensionUri);
        TaintFlowPanel.currentPanel._updateFindings(findings);
        return TaintFlowPanel.currentPanel;
    }
    static showSingleFinding(finding, extensionUri) {
        TaintFlowPanel.show([finding], extensionUri);
    }
    _updateFindings(findings) {
        this._findings = findings.filter(f => f.taintFlow);
        this._panel.webview.html = this._getHtmlContent();
    }
    _handleMessage(message) {
        switch (message.command) {
            case 'navigateToLocation':
                this._navigateToLocation(message.location);
                break;
            case 'showDetails':
                this._showFindingDetails(message.findingId);
                break;
            case 'copyPath':
                this._copyTaintPath(message.findingId);
                break;
        }
    }
    async _navigateToLocation(location) {
        try {
            const uri = vscode.Uri.file(location.file);
            const document = await vscode.workspace.openTextDocument(uri);
            const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);
            const line = Math.max(0, location.startLine - 1);
            const range = new vscode.Range(line, location.startColumn, line, location.endColumn);
            editor.selection = new vscode.Selection(range.start, range.end);
            editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
            const decoration = vscode.window.createTextEditorDecorationType({
                backgroundColor: 'rgba(255, 200, 0, 0.3)',
                isWholeLine: true,
                borderWidth: '2px',
                borderStyle: 'solid',
                borderColor: 'rgba(255, 150, 0, 0.8)'
            });
            editor.setDecorations(decoration, [range]);
            setTimeout(() => decoration.dispose(), 3000);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Could not navigate to location: ${error}`);
        }
    }
    _showFindingDetails(findingId) {
        const finding = this._findings.find(f => f.id === findingId);
        if (finding) {
            vscode.commands.executeCommand('appsec.showDetails', finding);
        }
    }
    _copyTaintPath(findingId) {
        const finding = this._findings.find(f => f.id === findingId);
        if (finding?.taintFlow) {
            const pathText = finding.taintFlow.path
                .map((node, i) => `${i + 1}. ${node.description}\n   at ${node.location.file}:${node.location.startLine}`)
                .join('\n');
            vscode.env.clipboard.writeText(pathText);
            vscode.window.showInformationMessage('Taint path copied to clipboard');
        }
    }
    _getHtmlContent() {
        const findingsData = JSON.stringify(this._findings.map(f => {
            // Handle inter-procedural data from backend
            const finding = f;
            return {
                id: f.id,
                title: f.title,
                type: f.type,
                severity: f.severity,
                cweId: f.cweId,
                owaspCategory: f.owaspCategory,
                confidence: f.confidence,
                location: f.location,
                codeSnippet: f.codeSnippet,
                // Inter-procedural analysis data
                callChain: finding.call_chain || finding.callChain || [],
                functionSummary: finding.function_summary || finding.functionSummary,
                crossFunctionFlow: finding.cross_function_flow,
                taintFlow: f.taintFlow ? {
                    source: f.taintFlow.source,
                    sink: f.taintFlow.sink,
                    path: f.taintFlow.path,
                    sanitizers: f.taintFlow.sanitizers
                } : null
            };
        }));
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Taint Flow Analysis - Premium</title>
    <style>
        :root {
            --bg-primary: #0a0e14;
            --bg-secondary: #12171f;
            --bg-tertiary: #1a2029;
            --bg-card: #151b24;
            --bg-node: #1c242f;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border-color: #2a3441;
            --border-glow: #3d4f65;
            --accent-blue: #58a6ff;
            --accent-cyan: #56d4dd;
            --accent-purple: #a371f7;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-orange: #db6d28;
            --accent-red: #f85149;
            --accent-pink: #db61a2;

            /* Node Colors */
            --src-primary: #ff6b6b;
            --src-secondary: #ee5a5a;
            --src-glow: rgba(255, 107, 107, 0.6);
            --prop-primary: #a78bfa;
            --prop-secondary: #8b5cf6;
            --prop-glow: rgba(167, 139, 250, 0.5);
            --sink-primary: #fbbf24;
            --sink-secondary: #f59e0b;
            --sink-glow: rgba(251, 191, 36, 0.6);
            --san-primary: #34d399;
            --san-secondary: #10b981;
            --san-glow: rgba(52, 211, 153, 0.5);

            /* Gradients */
            --gradient-header: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
            --gradient-card: linear-gradient(180deg, rgba(26, 32, 41, 0.8) 0%, rgba(21, 27, 36, 0.9) 100%);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* === HEADER === */
        .header {
            background: var(--gradient-header);
            padding: 20px 28px;
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(12px);
        }

        .header-content {
            max-width: 1600px;
            margin: 0 auto;
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .header h1 {
            font-size: 22px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 14px;
            background: linear-gradient(135deg, #fff 0%, #a0aec0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-icon {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #a78bfa 0%, #6366f1 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4);
        }

        .view-controls {
            display: flex;
            gap: 8px;
        }

        .view-btn {
            padding: 8px 14px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .view-btn:hover, .view-btn.active {
            background: var(--accent-purple);
            color: white;
            border-color: var(--accent-purple);
        }

        /* Stats Bar */
        .stats-bar {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }

        .stat-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 18px;
            background: rgba(26, 32, 41, 0.6);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .stat-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
            border-color: var(--border-glow);
        }

        .stat-indicator {
            position: relative;
            width: 12px;
            height: 12px;
        }

        .stat-indicator::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 50%;
            animation: pulse-ring 2s ease-out infinite;
        }

        .stat-indicator::after {
            content: '';
            position: absolute;
            inset: 2px;
            border-radius: 50%;
        }

        .stat-indicator.critical::before { background: rgba(248, 81, 73, 0.4); }
        .stat-indicator.critical::after { background: var(--accent-red); box-shadow: 0 0 10px var(--accent-red); }
        .stat-indicator.high::before { background: rgba(219, 109, 40, 0.4); }
        .stat-indicator.high::after { background: var(--accent-orange); box-shadow: 0 0 10px var(--accent-orange); }
        .stat-indicator.medium::before { background: rgba(210, 153, 34, 0.4); }
        .stat-indicator.medium::after { background: var(--accent-yellow); }
        .stat-indicator.low::before { background: rgba(63, 185, 80, 0.3); }
        .stat-indicator.low::after { background: var(--accent-green); }

        @keyframes pulse-ring {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(2.5); opacity: 0; }
        }

        .stat-value {
            font-size: 20px;
            font-weight: 800;
            font-variant-numeric: tabular-nums;
        }

        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 500;
        }

        /* === MAIN CONTENT === */
        .main-content {
            max-width: 1600px;
            margin: 0 auto;
            padding: 24px 28px;
        }

        /* Legend */
        .legend {
            display: flex;
            gap: 20px;
            padding: 14px 20px;
            background: var(--bg-secondary);
            border-radius: 14px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .legend-badge {
            width: 32px;
            height: 32px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
        }

        .legend-badge.src {
            background: linear-gradient(135deg, var(--src-primary), var(--src-secondary));
            box-shadow: 0 4px 12px var(--src-glow);
        }
        .legend-badge.prop {
            background: linear-gradient(135deg, var(--prop-primary), var(--prop-secondary));
            box-shadow: 0 4px 12px var(--prop-glow);
        }
        .legend-badge.sink {
            background: linear-gradient(135deg, var(--sink-primary), var(--sink-secondary));
            box-shadow: 0 4px 12px var(--sink-glow);
        }
        .legend-badge.san {
            background: linear-gradient(135deg, var(--san-primary), var(--san-secondary));
            box-shadow: 0 4px 12px var(--san-glow);
        }

        /* === FINDING CARD === */
        .finding-card {
            background: var(--gradient-card);
            border-radius: 16px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .finding-card:hover {
            border-color: var(--border-glow);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }

        .finding-header {
            padding: 18px 22px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            border-bottom: 1px solid transparent;
            transition: all 0.3s ease;
        }

        .finding-card:not(.collapsed) .finding-header {
            border-bottom-color: var(--border-color);
            background: rgba(26, 32, 41, 0.5);
        }

        .finding-title-section {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .severity-badge {
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .severity-critical {
            background: linear-gradient(135deg, rgba(248, 81, 73, 0.25), rgba(248, 81, 73, 0.15));
            color: var(--accent-red);
            border: 1px solid rgba(248, 81, 73, 0.4);
        }

        .severity-high {
            background: linear-gradient(135deg, rgba(219, 109, 40, 0.25), rgba(219, 109, 40, 0.15));
            color: var(--accent-orange);
            border: 1px solid rgba(219, 109, 40, 0.4);
        }

        .severity-medium {
            background: linear-gradient(135deg, rgba(210, 153, 34, 0.25), rgba(210, 153, 34, 0.15));
            color: var(--accent-yellow);
            border: 1px solid rgba(210, 153, 34, 0.4);
        }

        .severity-low {
            background: linear-gradient(135deg, rgba(63, 185, 80, 0.25), rgba(63, 185, 80, 0.15));
            color: var(--accent-green);
            border: 1px solid rgba(63, 185, 80, 0.4);
        }

        .finding-type {
            font-size: 15px;
            font-weight: 600;
        }

        .finding-meta {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .meta-tag {
            padding: 4px 10px;
            background: var(--bg-primary);
            border-radius: 6px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 11px;
            color: var(--text-secondary);
        }

        .expand-btn {
            width: 30px;
            height: 30px;
            border-radius: 8px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .expand-btn:hover {
            background: var(--accent-purple);
            color: white;
            border-color: var(--accent-purple);
        }

        .expand-icon {
            transition: transform 0.3s ease;
            font-size: 12px;
        }

        .finding-card.collapsed .expand-icon {
            transform: rotate(-90deg);
        }

        .finding-card.collapsed .finding-body {
            display: none;
        }

        /* Finding Body */
        .finding-body {
            padding: 22px;
        }

        /* Info Grid */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 14px;
            margin-bottom: 22px;
        }

        .info-card {
            background: var(--bg-node);
            border-radius: 10px;
            padding: 14px 16px;
            border: 1px solid var(--border-color);
            transition: all 0.2s ease;
        }

        .info-card:hover {
            border-color: var(--accent-cyan);
            transform: translateY(-1px);
        }

        .info-label {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 6px;
            font-weight: 500;
        }

        .info-value {
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-cyan);
        }

        .info-value a {
            color: var(--accent-cyan);
            text-decoration: none;
        }

        .info-value a:hover {
            text-decoration: underline;
        }

        /* === SVG FLOW VISUALIZATION === */
        .flow-section {
            margin-bottom: 22px;
        }

        .flow-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }

        .flow-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .flow-controls {
            display: flex;
            gap: 6px;
        }

        .flow-ctrl-btn {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: var(--bg-node);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }

        .flow-ctrl-btn:hover {
            background: var(--accent-purple);
            color: white;
            border-color: var(--accent-purple);
        }

        .flow-container {
            background: var(--bg-primary);
            border-radius: 14px;
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
            min-height: 400px;
        }

        .flow-canvas-wrapper {
            width: 100%;
            height: 100%;
            overflow: auto;
            position: relative;
        }

        .flow-canvas {
            cursor: grab;
            min-width: 100%;
            min-height: 400px;
        }

        .flow-canvas:active {
            cursor: grabbing;
        }

        /* SVG Styles */
        .svg-flow-container {
            width: 100%;
            min-height: 400px;
        }

        /* Flow Node SVG Styling */
        .flow-node-group {
            cursor: pointer;
            transition: transform 0.2s ease;
        }

        .flow-node-group:hover {
            transform: scale(1.02);
        }

        .node-bg {
            transition: all 0.3s ease;
        }

        .flow-node-group:hover .node-bg {
            filter: brightness(1.1);
        }

        .node-glow {
            opacity: 0.6;
            transition: opacity 0.3s ease;
        }

        .flow-node-group:hover .node-glow {
            opacity: 1;
        }

        /* Edge Animation */
        .flow-edge-path {
            fill: none;
            stroke-width: 2;
            stroke-linecap: round;
        }

        .flow-particle {
            fill: #fff;
            filter: blur(1px);
        }

        @keyframes flowParticle {
            0% { offset-distance: 0%; opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { offset-distance: 100%; opacity: 0; }
        }

        /* Mini-map */
        .minimap {
            position: absolute;
            bottom: 12px;
            right: 12px;
            width: 140px;
            height: 100px;
            background: rgba(10, 14, 20, 0.9);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            z-index: 10;
        }

        .minimap-viewport {
            position: absolute;
            border: 2px solid var(--accent-cyan);
            background: rgba(88, 166, 255, 0.1);
            pointer-events: none;
        }

        /* Zoom indicator */
        .zoom-indicator {
            position: absolute;
            bottom: 12px;
            left: 12px;
            padding: 6px 12px;
            background: rgba(10, 14, 20, 0.9);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 11px;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            z-index: 10;
        }

        /* Code Preview in Tooltip */
        .node-tooltip {
            position: absolute;
            background: var(--bg-card);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            padding: 14px 16px;
            max-width: 400px;
            z-index: 100;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
            opacity: 0;
            visibility: hidden;
            transform: translateY(10px);
            transition: all 0.2s ease;
            pointer-events: none;
        }

        .node-tooltip.visible {
            opacity: 1;
            visibility: visible;
            transform: translateY(0);
        }

        .tooltip-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }

        .tooltip-type {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 9px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .tooltip-type.src { background: var(--src-primary); color: #000; }
        .tooltip-type.prop { background: var(--prop-primary); color: #000; }
        .tooltip-type.sink { background: var(--sink-primary); color: #000; }
        .tooltip-type.san { background: var(--san-primary); color: #000; }

        .tooltip-desc {
            font-size: 13px;
            font-weight: 500;
        }

        .tooltip-code {
            background: #0d1117;
            border-radius: 8px;
            padding: 10px 12px;
            margin: 10px 0;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 11px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }

        .tooltip-code .line-num {
            color: var(--text-muted);
            margin-right: 12px;
            user-select: none;
        }

        .tooltip-var {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid var(--border-color);
        }

        .tooltip-var-label {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .tooltip-var-value {
            padding: 2px 8px;
            background: rgba(167, 139, 250, 0.2);
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: var(--accent-purple);
        }

        .tooltip-location {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-top: 8px;
            font-size: 11px;
            color: var(--text-muted);
        }

        /* Code Section */
        .code-section {
            margin-bottom: 22px;
        }

        .code-preview {
            background: #0d1117;
            border-radius: 10px;
            padding: 14px 18px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 12px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            position: relative;
        }

        .code-preview-label {
            position: absolute;
            top: -9px;
            left: 14px;
            background: var(--bg-card);
            padding: 2px 10px;
            font-size: 9px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            border-radius: 4px;
            font-family: 'Inter', sans-serif;
        }

        .line-number {
            color: var(--text-muted);
            margin-right: 16px;
            user-select: none;
        }

        .code-highlight {
            background: rgba(248, 81, 73, 0.12);
            padding: 4px 8px;
            border-radius: 4px;
            border-left: 3px solid var(--accent-red);
        }

        /* Actions */
        .actions-bar {
            display: flex;
            gap: 10px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
            flex-wrap: wrap;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-purple), #6366f1);
            color: white;
            box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5);
        }

        .btn-secondary {
            background: var(--bg-node);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: var(--bg-tertiary);
            border-color: var(--accent-cyan);
        }

        /* No Findings */
        .no-findings {
            text-align: center;
            padding: 80px 40px;
            background: var(--bg-secondary);
            border-radius: 16px;
            border: 1px solid var(--border-color);
        }

        .no-findings-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--accent-green), #059669);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 20px;
            box-shadow: 0 8px 32px rgba(52, 211, 153, 0.4);
        }

        .no-findings h2 {
            font-size: 22px;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #fff 0%, #a0aec0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .no-findings p {
            color: var(--text-secondary);
            font-size: 14px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header { padding: 14px; }
            .main-content { padding: 14px; }
            .stats-bar { gap: 10px; }
            .flow-container { min-height: 300px; }
            .minimap { display: none; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="header-top">
                <h1>
                    <div class="header-icon">&#128270;</div>
                    Taint Flow Analysis
                </h1>
                <div class="view-controls">
                    <button class="view-btn active" onclick="setViewMode('diagram')">Diagram</button>
                    <button class="view-btn" onclick="setViewMode('list')">List</button>
                </div>
            </div>
            <div class="stats-bar">
                <div class="stat-item">
                    <span class="stat-value">${this._findings.length}</span>
                    <span class="stat-label">Total Flows</span>
                </div>
                <div class="stat-item">
                    <div class="stat-indicator critical"></div>
                    <span class="stat-value">${this._findings.filter(f => f.severity === 'critical').length}</span>
                    <span class="stat-label">Critical</span>
                </div>
                <div class="stat-item">
                    <div class="stat-indicator high"></div>
                    <span class="stat-value">${this._findings.filter(f => f.severity === 'high').length}</span>
                    <span class="stat-label">High</span>
                </div>
                <div class="stat-item">
                    <div class="stat-indicator medium"></div>
                    <span class="stat-value">${this._findings.filter(f => f.severity === 'medium').length}</span>
                    <span class="stat-label">Medium</span>
                </div>
                <div class="stat-item">
                    <div class="stat-indicator low"></div>
                    <span class="stat-value">${this._findings.filter(f => f.severity === 'low').length}</span>
                    <span class="stat-label">Low</span>
                </div>
            </div>
        </div>
    </div>

    <div class="main-content">
        <div class="legend">
            <div class="legend-item">
                <div class="legend-badge src">S</div>
                <span>Taint Source</span>
            </div>
            <div class="legend-item">
                <div class="legend-badge prop">P</div>
                <span>Propagator</span>
            </div>
            <div class="legend-item">
                <div class="legend-badge sink">!</div>
                <span>Sink (Vuln)</span>
            </div>
            <div class="legend-item">
                <div class="legend-badge san">&#10003;</div>
                <span>Sanitizer</span>
            </div>
        </div>

        <div id="findings-container">
            ${this._findings.length > 0
            ? this._findings.map((f, idx) => this._renderFindingCard(f, idx)).join('')
            : this._renderNoFindings()}
        </div>
    </div>

    <div id="node-tooltip" class="node-tooltip"></div>

    <script>
        const vscode = acquireVsCodeApi();
        const findings = ${findingsData};
        let currentZoom = 1;
        let panX = 0, panY = 0;
        let isDragging = false;
        let dragStart = { x: 0, y: 0 };

        function navigateToLocation(location) {
            vscode.postMessage({
                command: 'navigateToLocation',
                location: location
            });
        }

        function showDetails(findingId) {
            vscode.postMessage({
                command: 'showDetails',
                findingId: findingId
            });
        }

        function copyPath(findingId) {
            vscode.postMessage({
                command: 'copyPath',
                findingId: findingId
            });
        }

        function toggleCard(event, header) {
            if (event.target.closest('.expand-btn')) return;
            const card = header.closest('.finding-card');
            card.classList.toggle('collapsed');
        }

        function setViewMode(mode) {
            document.querySelectorAll('.view-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
        }

        // Zoom controls
        function zoomIn(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (canvas && currentZoom < 2) {
                currentZoom += 0.2;
                updateCanvasTransform(canvas);
            }
        }

        function zoomOut(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (canvas && currentZoom > 0.5) {
                currentZoom -= 0.2;
                updateCanvasTransform(canvas);
            }
        }

        function resetView(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (canvas) {
                currentZoom = 1;
                panX = 0;
                panY = 0;
                updateCanvasTransform(canvas);
            }
        }

        function updateCanvasTransform(canvas) {
            const svg = canvas.querySelector('svg');
            if (svg) {
                svg.style.transform = 'scale(' + currentZoom + ') translate(' + panX + 'px, ' + panY + 'px)';
                svg.style.transformOrigin = 'center center';
            }
            const zoomIndicator = canvas.parentElement.querySelector('.zoom-indicator');
            if (zoomIndicator) {
                zoomIndicator.textContent = Math.round(currentZoom * 100) + '%';
            }
        }

        // Pan functionality
        function initPan(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return;

            canvas.addEventListener('mousedown', (e) => {
                if (e.target.closest('.flow-node-group')) return;
                isDragging = true;
                dragStart = { x: e.clientX - panX, y: e.clientY - panY };
                canvas.style.cursor = 'grabbing';
            });

            canvas.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                panX = e.clientX - dragStart.x;
                panY = e.clientY - dragStart.y;
                updateCanvasTransform(canvas);
            });

            canvas.addEventListener('mouseup', () => {
                isDragging = false;
                canvas.style.cursor = 'grab';
            });

            canvas.addEventListener('mouseleave', () => {
                isDragging = false;
                canvas.style.cursor = 'grab';
            });

            // Scroll to zoom
            canvas.addEventListener('wheel', (e) => {
                e.preventDefault();
                if (e.deltaY < 0 && currentZoom < 2) {
                    currentZoom += 0.1;
                } else if (e.deltaY > 0 && currentZoom > 0.5) {
                    currentZoom -= 0.1;
                }
                updateCanvasTransform(canvas);
            });
        }

        // Node tooltip
        function showNodeTooltip(event, nodeData) {
            const tooltip = document.getElementById('node-tooltip');
            const data = JSON.parse(decodeURIComponent(nodeData));

            let typeClass = 'prop';
            let typeLabel = 'PROPAGATOR';
            if (data.type === 'source') { typeClass = 'src'; typeLabel = 'SOURCE'; }
            else if (data.type === 'sink') { typeClass = 'sink'; typeLabel = 'SINK'; }
            else if (data.type === 'sanitizer') { typeClass = 'san'; typeLabel = 'SANITIZER'; }

            tooltip.innerHTML =
                '<div class="tooltip-header">' +
                    '<span class="tooltip-type ' + typeClass + '">' + typeLabel + '</span>' +
                    '<span class="tooltip-desc">' + data.description + '</span>' +
                '</div>' +
                (data.code ? '<div class="tooltip-code"><span class="line-num">' + data.line + '</span>' + escapeHtml(data.code) + '</div>' : '') +
                (data.variable ? '<div class="tooltip-var"><span class="tooltip-var-label">Variable:</span><span class="tooltip-var-value">' + data.variable + '</span></div>' : '') +
                '<div class="tooltip-location">&#128205; ' + data.file + ':' + data.line + '</div>';

            const rect = event.target.closest('.flow-node-group').getBoundingClientRect();
            tooltip.style.left = (rect.right + 15) + 'px';
            tooltip.style.top = rect.top + 'px';
            tooltip.classList.add('visible');
        }

        function hideNodeTooltip() {
            document.getElementById('node-tooltip').classList.remove('visible');
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Initialize all canvases
        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('.flow-canvas').forEach(canvas => {
                initPan(canvas.id);
            });
        });

        // Click handlers for nodes
        document.querySelectorAll('.flow-node-group').forEach(node => {
            node.addEventListener('click', () => {
                const locationData = node.dataset.location;
                if (locationData) {
                    navigateToLocation(JSON.parse(locationData));
                }
            });
        });
    </script>
</body>
</html>`;
    }
    _renderNoFindings() {
        return `
            <div class="no-findings">
                <div class="no-findings-icon">✓</div>
                <h2>No Taint Flows Detected</h2>
                <p>Great news! No data flow vulnerabilities were found in the scanned code.</p>
            </div>
        `;
    }
    _renderFindingCard(finding, index) {
        if (!finding.taintFlow)
            return '';
        const flow = finding.taintFlow;
        const canvasId = `flow-canvas-${index}`;
        const flowSvg = this._renderSvgFlowDiagram(flow, canvasId);
        return `
        <div class="finding-card" id="finding-${finding.id}">
            <div class="finding-header" onclick="toggleCard(event, this)">
                <div class="finding-title-section">
                    <span class="severity-badge severity-${finding.severity}">${finding.severity}</span>
                    <span class="finding-type">${finding.title}</span>
                </div>
                <div class="finding-meta">
                    <span class="meta-tag">${finding.cweId || 'N/A'}</span>
                    <span class="meta-tag">${finding.location.file.split('/').pop()}:${finding.location.startLine}</span>
                    <button class="expand-btn">
                        <span class="expand-icon">&#9660;</span>
                    </button>
                </div>
            </div>

            <div class="finding-body">
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Vulnerability Type</div>
                        <div class="info-value">${finding.type.replace(/-/g, ' ').toUpperCase()}</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">CWE ID</div>
                        <div class="info-value">
                            <a href="https://cwe.mitre.org/data/definitions/${(finding.cweId || '').replace('CWE-', '')}.html" target="_blank">
                                ${finding.cweId || 'N/A'}
                            </a>
                        </div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">OWASP Category</div>
                        <div class="info-value">${finding.owaspCategory || 'N/A'}</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Confidence</div>
                        <div class="info-value">${finding.confidence.toUpperCase()}</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Flow Steps</div>
                        <div class="info-value">${flow.path.length} nodes</div>
                    </div>
                </div>

                ${this._renderCallChainSection(finding)}

                <div class="flow-section">
                    <div class="flow-header">
                        <div class="flow-title">
                            <span>&#128202;</span>
                            Data Flow Visualization
                        </div>
                        <div class="flow-controls">
                            <button class="flow-ctrl-btn" onclick="zoomOut('${canvasId}')" title="Zoom Out">-</button>
                            <button class="flow-ctrl-btn" onclick="zoomIn('${canvasId}')" title="Zoom In">+</button>
                            <button class="flow-ctrl-btn" onclick="resetView('${canvasId}')" title="Reset View">&#8634;</button>
                        </div>
                    </div>
                    <div class="flow-container">
                        <div class="flow-canvas" id="${canvasId}">
                            ${flowSvg}
                        </div>
                        <div class="zoom-indicator">100%</div>
                        <div class="minimap" id="minimap-${index}">
                            <div class="minimap-viewport"></div>
                        </div>
                    </div>
                </div>

                <div class="code-section">
                    <div class="code-preview">
                        <span class="code-preview-label">Vulnerable Code</span>
                        <span class="line-number">${finding.location.startLine}</span>
                        <span class="code-highlight">${this._escapeHtml(finding.codeSnippet)}</span>
                    </div>
                </div>

                <div class="actions-bar">
                    <button class="btn btn-primary" onclick="showDetails('${finding.id}')">
                        &#128203; View Details
                    </button>
                    <button class="btn btn-secondary" onclick="copyPath('${finding.id}')">
                        &#128203; Copy Flow Path
                    </button>
                    <button class="btn btn-secondary" onclick="navigateToLocation(${JSON.stringify(finding.location)})">
                        &#128205; Go to Source
                    </button>
                </div>
            </div>
        </div>`;
    }
    _renderCallChainSection(finding) {
        const findingAny = finding;
        const callChain = findingAny.call_chain || findingAny.callChain || [];
        const functionSummary = findingAny.function_summary || findingAny.functionSummary;
        if (callChain.length === 0 && !functionSummary) {
            return '';
        }
        let html = `
        <div style="margin-bottom: 22px; padding: 18px; background: linear-gradient(135deg, rgba(167, 139, 250, 0.1), rgba(99, 102, 241, 0.05)); border-radius: 12px; border: 1px solid rgba(167, 139, 250, 0.3);">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 14px;">
                <span style="font-size: 18px;">&#128279;</span>
                <span style="font-size: 14px; font-weight: 600; color: var(--accent-purple);">Inter-Procedural Analysis</span>
            </div>
        `;
        // Render call chain
        if (callChain.length > 0) {
            html += `
            <div style="margin-bottom: 16px;">
                <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 10px;">Cross-Function Call Chain</div>
                <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 8px;">
            `;
            callChain.forEach((func, idx) => {
                const isFirst = idx === 0;
                const isLast = idx === callChain.length - 1;
                const bgColor = isFirst ? 'rgba(255, 107, 107, 0.2)' : isLast ? 'rgba(251, 191, 36, 0.2)' : 'rgba(167, 139, 250, 0.15)';
                const borderColor = isFirst ? 'var(--src-primary)' : isLast ? 'var(--sink-primary)' : 'var(--prop-primary)';
                const icon = isFirst ? '&#128229;' : isLast ? '&#9888;' : '&#128260;';
                html += `
                    <div style="display: flex; flex-direction: column; align-items: center; gap: 4px;">
                        <span style="font-size: 10px; color: var(--text-muted);">${isFirst ? 'Entry' : isLast ? 'Sink' : 'Flow'}</span>
                        <div style="padding: 8px 14px; background: ${bgColor}; border: 1px solid ${borderColor}; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-primary);">
                            <span style="margin-right: 6px;">${icon}</span>${this._escapeHtml(func)}
                        </div>
                    </div>
                `;
                if (!isLast) {
                    html += `<span style="color: var(--accent-purple); font-size: 16px;">&#8594;</span>`;
                }
            });
            html += `</div></div>`;
        }
        // Render function summary if available
        if (functionSummary) {
            html += `
            <div style="padding: 12px; background: var(--bg-primary); border-radius: 8px; border: 1px solid var(--border-color);">
                <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 8px;">Function Summary</div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px;">
                    <div>
                        <span style="font-size: 10px; color: var(--text-muted);">Name</span>
                        <div style="font-size: 12px; color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${this._escapeHtml(functionSummary.name || 'N/A')}</div>
                    </div>
                    ${functionSummary.taint_behavior ? `
                    <div>
                        <span style="font-size: 10px; color: var(--text-muted);">Taint Behavior</span>
                        <div style="font-size: 12px; color: var(--sink-primary);">${this._escapeHtml(functionSummary.taint_behavior)}</div>
                    </div>
                    ` : ''}
                    ${functionSummary.returns_tainted !== undefined ? `
                    <div>
                        <span style="font-size: 10px; color: var(--text-muted);">Returns Tainted</span>
                        <div style="font-size: 12px; color: ${functionSummary.returns_tainted ? 'var(--accent-red)' : 'var(--accent-green)'};">${functionSummary.returns_tainted ? 'Yes' : 'No'}</div>
                    </div>
                    ` : ''}
                </div>
            </div>
            `;
        }
        html += `</div>`;
        return html;
    }
    _renderSvgFlowDiagram(flow, canvasId) {
        const path = flow.path;
        const nodeWidth = 320;
        const nodeHeight = 90;
        const nodeSpacingY = 50;
        const startX = 40;
        const startY = 30;
        const totalHeight = startY + (path.length * (nodeHeight + nodeSpacingY)) + 40;
        const svgWidth = nodeWidth + (startX * 2) + 100;
        let svgContent = `
            <svg class="svg-flow-container" width="100%" height="${totalHeight}" viewBox="0 0 ${svgWidth} ${totalHeight}" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <!-- Gradients -->
                    <linearGradient id="srcGrad-${canvasId}" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#ff6b6b"/>
                        <stop offset="100%" style="stop-color:#ee5a5a"/>
                    </linearGradient>
                    <linearGradient id="propGrad-${canvasId}" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#a78bfa"/>
                        <stop offset="100%" style="stop-color:#8b5cf6"/>
                    </linearGradient>
                    <linearGradient id="sinkGrad-${canvasId}" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#fbbf24"/>
                        <stop offset="100%" style="stop-color:#f59e0b"/>
                    </linearGradient>
                    <linearGradient id="sanGrad-${canvasId}" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#34d399"/>
                        <stop offset="100%" style="stop-color:#10b981"/>
                    </linearGradient>
                    <linearGradient id="edgeGrad-${canvasId}" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" style="stop-color:#a78bfa"/>
                        <stop offset="50%" style="stop-color:#56d4dd"/>
                        <stop offset="100%" style="stop-color:#fbbf24"/>
                    </linearGradient>

                    <!-- Glow Filters -->
                    <filter id="srcGlow-${canvasId}" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="8" result="blur"/>
                        <feFlood flood-color="#ff6b6b" flood-opacity="0.5"/>
                        <feComposite in2="blur" operator="in"/>
                        <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="propGlow-${canvasId}" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="6" result="blur"/>
                        <feFlood flood-color="#a78bfa" flood-opacity="0.4"/>
                        <feComposite in2="blur" operator="in"/>
                        <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="sinkGlow-${canvasId}" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="8" result="blur"/>
                        <feFlood flood-color="#fbbf24" flood-opacity="0.5"/>
                        <feComposite in2="blur" operator="in"/>
                        <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="sanGlow-${canvasId}" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="6" result="blur"/>
                        <feFlood flood-color="#34d399" flood-opacity="0.4"/>
                        <feComposite in2="blur" operator="in"/>
                        <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>

                    <!-- Arrow Marker -->
                    <marker id="arrowhead-${canvasId}" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="url(#edgeGrad-${canvasId})"/>
                    </marker>

                    <!-- Animated Particle -->
                    <circle id="particle-${canvasId}" r="4" fill="#fff">
                        <animate attributeName="opacity" values="0;1;1;0" dur="2s" repeatCount="indefinite"/>
                    </circle>
                </defs>

                <!-- Background Grid -->
                <pattern id="grid-${canvasId}" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(42, 52, 65, 0.3)" stroke-width="0.5"/>
                </pattern>
                <rect width="100%" height="100%" fill="url(#grid-${canvasId})"/>
        `;
        // Draw edges first (behind nodes)
        for (let i = 0; i < path.length - 1; i++) {
            const y1 = startY + (i * (nodeHeight + nodeSpacingY)) + nodeHeight;
            const y2 = startY + ((i + 1) * (nodeHeight + nodeSpacingY));
            const centerX = startX + (nodeWidth / 2);
            // Curved edge path
            const controlOffset = nodeSpacingY / 2;
            svgContent += `
                <path class="flow-edge-path"
                      d="M ${centerX} ${y1} C ${centerX} ${y1 + controlOffset}, ${centerX} ${y2 - controlOffset}, ${centerX} ${y2}"
                      stroke="url(#edgeGrad-${canvasId})"
                      stroke-dasharray="4,4"
                      marker-end="url(#arrowhead-${canvasId})">
                    <animate attributeName="stroke-dashoffset" from="8" to="0" dur="0.5s" repeatCount="indefinite"/>
                </path>

                <!-- Animated particle along the path -->
                <circle r="5" fill="#56d4dd" opacity="0.8">
                    <animateMotion dur="1.5s" repeatCount="indefinite">
                        <mpath href="#edge-path-${canvasId}-${i}"/>
                    </animateMotion>
                    <animate attributeName="opacity" values="0;1;1;0" dur="1.5s" repeatCount="indefinite"/>
                </circle>
                <path id="edge-path-${canvasId}-${i}"
                      d="M ${centerX} ${y1} C ${centerX} ${y1 + controlOffset}, ${centerX} ${y2 - controlOffset}, ${centerX} ${y2}"
                      fill="none" stroke="none"/>
            `;
        }
        // Draw nodes
        for (let i = 0; i < path.length; i++) {
            const node = path[i];
            const isFirst = i === 0;
            const isLast = i === path.length - 1;
            let nodeType = 'prop';
            let gradientId = `propGrad-${canvasId}`;
            let filterId = `propGlow-${canvasId}`;
            let label = 'PROPAGATOR';
            let iconChar = 'P';
            let textColor = '#a78bfa';
            if (isFirst) {
                nodeType = 'src';
                gradientId = `srcGrad-${canvasId}`;
                filterId = `srcGlow-${canvasId}`;
                label = 'SOURCE';
                iconChar = 'S';
                textColor = '#ff6b6b';
            }
            else if (isLast) {
                nodeType = 'sink';
                gradientId = `sinkGrad-${canvasId}`;
                filterId = `sinkGlow-${canvasId}`;
                label = 'SINK';
                iconChar = '!';
                textColor = '#fbbf24';
            }
            // Check if sanitizer
            const isSanitizer = flow.sanitizers.some(s => node.description.toLowerCase().includes(s.name.toLowerCase()));
            if (isSanitizer) {
                nodeType = 'san';
                gradientId = `sanGrad-${canvasId}`;
                filterId = `sanGlow-${canvasId}`;
                label = 'SANITIZER';
                iconChar = '&#10003;';
                textColor = '#34d399';
            }
            const x = startX;
            const y = startY + (i * (nodeHeight + nodeSpacingY));
            const fileName = node.location.file.split('/').pop() || 'unknown';
            const shortDesc = node.description.length > 40 ? node.description.substring(0, 37) + '...' : node.description;
            // Extract variable name from description
            const varMatch = node.description.match(/variable\s+['\`]?(\w+)['\`]?/i) ||
                node.description.match(/parameter\s+['\`]?(\w+)['\`]?/i) ||
                node.description.match(/['\`](\w+)['\`]/);
            const variable = varMatch ? varMatch[1] : '';
            // Create tooltip data
            const tooltipData = encodeURIComponent(JSON.stringify({
                type: nodeType === 'src' ? 'source' : nodeType === 'sink' ? 'sink' : nodeType === 'san' ? 'sanitizer' : 'propagator',
                description: node.description,
                file: fileName,
                line: node.location.startLine,
                code: node.description.substring(0, 60),
                variable: variable
            }));
            const locationJson = JSON.stringify(node.location).replace(/"/g, '&quot;');
            svgContent += `
                <g class="flow-node-group"
                   data-location="${locationJson}"
                   data-node-info="${tooltipData}"
                   onmouseenter="showNodeTooltip(event, '${tooltipData}')"
                   onmouseleave="hideNodeTooltip()">

                    <!-- Node Glow Background -->
                    <rect class="node-glow" x="${x - 4}" y="${y - 4}" width="${nodeWidth + 8}" height="${nodeHeight + 8}"
                          rx="16" ry="16" fill="none" stroke="url(#${gradientId})" stroke-width="2"
                          filter="url(#${filterId})" opacity="0.3"/>

                    <!-- Node Background -->
                    <rect class="node-bg" x="${x}" y="${y}" width="${nodeWidth}" height="${nodeHeight}"
                          rx="12" ry="12" fill="#1c242f" stroke="url(#${gradientId})" stroke-width="2"/>

                    <!-- Left Accent Bar -->
                    <rect x="${x}" y="${y}" width="4" height="${nodeHeight}"
                          rx="2" ry="2" fill="url(#${gradientId})"/>

                    <!-- Icon Circle -->
                    <circle cx="${x + 35}" cy="${y + (nodeHeight / 2)}" r="18" fill="url(#${gradientId})"/>
                    <text x="${x + 35}" y="${y + (nodeHeight / 2) + 5}"
                          text-anchor="middle" fill="#0a0e14" font-size="14" font-weight="700">${iconChar}</text>

                    <!-- Label -->
                    <text x="${x + 65}" y="${y + 22}" fill="${textColor}"
                          font-size="9" font-weight="700" letter-spacing="1">${label}</text>

                    <!-- Description -->
                    <text x="${x + 65}" y="${y + 42}" fill="#e6edf3"
                          font-size="12" font-weight="500">${this._escapeHtml(shortDesc)}</text>

                    <!-- Location -->
                    <text x="${x + 65}" y="${y + 62}" fill="#6e7681"
                          font-size="10" font-family="JetBrains Mono, monospace">
                        &#128205; ${fileName}:${node.location.startLine}:${node.location.startColumn}
                    </text>

                    ${variable ? `
                    <!-- Variable Tag -->
                    <rect x="${x + nodeWidth - 80}" y="${y + 12}" width="68" height="20"
                          rx="4" ry="4" fill="rgba(167, 139, 250, 0.2)" stroke="rgba(167, 139, 250, 0.4)" stroke-width="1"/>
                    <text x="${x + nodeWidth - 46}" y="${y + 26}"
                          text-anchor="middle" fill="#a78bfa" font-size="10" font-family="JetBrains Mono, monospace">${variable}</text>
                    ` : ''}

                    <!-- Step Number -->
                    <circle cx="${x + nodeWidth - 12}" cy="${y + nodeHeight - 12}" r="10"
                            fill="#0a0e14" stroke="#2a3441" stroke-width="1"/>
                    <text x="${x + nodeWidth - 12}" y="${y + nodeHeight - 8}"
                          text-anchor="middle" fill="#8b949e" font-size="9" font-weight="600">${i + 1}</text>
                </g>
            `;
        }
        svgContent += `</svg>`;
        return svgContent;
    }
    _escapeHtml(text) {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    dispose() {
        TaintFlowPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
exports.TaintFlowPanel = TaintFlowPanel;
//# sourceMappingURL=taintFlowPanel.js.map