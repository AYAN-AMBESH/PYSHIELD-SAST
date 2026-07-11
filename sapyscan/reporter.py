import os
import json
from typing import List, Dict, Any

class ReportGenerator:
    @staticmethod
    def render_html(results: List[Dict[str, Any]], target_dir: str, output_path: str):
        findings_json = json.dumps(results)
        target_dir_escaped = target_dir.replace("\\", "\\\\").replace("'", "\\'")
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SaPyScan Security Vulnerability Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #080d16;
            --bg-secondary: #0f172a;
            --bg-card: #131d31;
            --bg-hover: #1e293b;
            --border-color: #202e48;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            
            --color-critical: #f43f5e;
            --color-high: #f97316;
            --color-medium: #eab308;
            --color-low: #3b82f6;
            --color-info: #10b981;
            
            --glow-critical: rgba(244, 63, 94, 0.12);
            --glow-high: rgba(249, 115, 22, 0.12);
            --glow-medium: rgba(234, 179, 8, 0.12);
            --glow-low: rgba(59, 130, 246, 0.12);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            padding-bottom: 80px;
        }}

        /* Header */
        .app-header {{
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(8, 13, 22, 0) 100%);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-color);
            padding: 24px 40px;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .header-container {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
        }}

        .logo-section {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .logo-shield {{
            font-size: 32px;
            filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.3));
        }}

        .logo-text h1 {{
            font-size: 22px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #ffffff 0%, #cbd5e1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .logo-sub {{
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .target-section {{
            display: flex;
            flex-direction: column;
            gap: 4px;
            align-items: flex-end;
        }}

        .target-meta {{
            font-size: 12px;
        }}

        .meta-label {{
            color: var(--text-muted);
            font-weight: 600;
            margin-right: 6px;
        }}

        .meta-value {{
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
        }}

        /* Main Container */
        .app-container {{
            max-width: 1400px;
            margin: 32px auto;
            padding: 0 40px;
        }}

        /* Stats Cards */
        .stats-row {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }}

        .stat-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            position: relative;
            overflow: hidden;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        .stat-card:hover {{
            transform: translateY(-4px);
            border-color: var(--text-muted);
        }}

        .stat-num {{
            font-size: 36px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 8px;
            font-family: 'JetBrains Mono', monospace;
        }}

        .stat-label {{
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 500;
        }}

        .stat-glow {{
            position: absolute;
            top: 0;
            right: 0;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            filter: blur(30px);
            opacity: 0.15;
        }}

        /* Specific card accents */
        .stat-card.total {{ border-bottom: 3px solid #8b5cf6; }}
        .stat-card.total .stat-num {{ color: #c084fc; }}
        .stat-card.total .stat-glow {{ background: #8b5cf6; }}

        .stat-card.critical {{ border-bottom: 3px solid var(--color-critical); }}
        .stat-card.critical .stat-num {{ color: var(--color-critical); }}
        .stat-card.critical .stat-glow {{ background: var(--color-critical); }}

        .stat-card.high {{ border-bottom: 3px solid var(--color-high); }}
        .stat-card.high .stat-num {{ color: var(--color-high); }}
        .stat-card.high .stat-glow {{ background: var(--color-high); }}

        .stat-card.medium {{ border-bottom: 3px solid var(--color-medium); }}
        .stat-card.medium .stat-num {{ color: var(--color-medium); }}
        .stat-card.medium .stat-glow {{ background: var(--color-medium); }}

        .stat-card.low {{ border-bottom: 3px solid var(--color-low); }}
        .stat-card.low .stat-num {{ color: var(--color-low); }}
        .stat-card.low .stat-glow {{ background: var(--color-low); }}

        /* Workspace Grid */
        .workspace {{
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 32px;
        }}

        @media (max-width: 1100px) {{
            .workspace {{
                grid-template-columns: 1fr;
            }}
        }}

        /* Controls */
        .controls-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .search-box {{
            display: flex;
            align-items: center;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 10px 16px;
            gap: 12px;
        }}

        .search-box input {{
            background: none;
            border: none;
            outline: none;
            color: var(--text-primary);
            width: 100%;
            font-size: 14px;
            font-family: inherit;
        }}

        .search-box input::placeholder {{
            color: var(--text-muted);
        }}

        .clear-search {{
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 14px;
        }}

        .clear-search:hover {{
            color: var(--text-primary);
        }}

        .filter-tabs {{
            display: flex;
            gap: 8px;
            overflow-x: auto;
        }}

        .tab-btn {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
            white-space: nowrap;
        }}

        .tab-btn:hover {{
            border-color: var(--text-muted);
            color: var(--text-primary);
        }}

        .tab-btn.active {{
            background-color: var(--bg-hover);
            border-color: #3b82f6;
            color: var(--text-primary);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.15);
        }}

        .tab-badge {{
            background-color: rgba(255, 255, 255, 0.08);
            padding: 2px 6px;
            border-radius: 6px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* Findings List */
        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .finding-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            overflow: hidden;
            transition: all 0.3s ease;
        }}

        .finding-card:hover {{
            border-color: var(--text-muted);
        }}

        .finding-card.border-critical {{ border-left: 4px solid var(--color-critical); }}
        .finding-card.border-high {{ border-left: 4px solid var(--color-high); }}
        .finding-card.border-medium {{ border-left: 4px solid var(--color-medium); }}
        .finding-card.border-low {{ border-left: 4px solid var(--color-low); }}
        .finding-card.border-info {{ border-left: 4px solid var(--color-info); }}

        .finding-header {{
            padding: 20px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background-color: rgba(255, 255, 255, 0.01);
        }}

        .finding-header:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        .finding-title-group {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .finding-title {{
            font-size: 16px;
            font-weight: 600;
        }}

        .finding-sub {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 12px;
        }}

        .finding-rule {{
            color: #93c5fd;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
        }}

        .finding-loc {{
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}

        .assessment-badge {
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 6px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-secondary);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .assessment-badge.confirmed {
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-info);
            border-color: rgba(16, 185, 129, 0.18);
        }

        .assessment-badge.needs_review {
            background: rgba(234, 179, 8, 0.1);
            color: var(--color-medium);
            border-color: rgba(234, 179, 8, 0.18);
        }

        .header-right {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .severity-badge {{
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 6px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        .severity-badge.critical {{ background: rgba(244, 63, 94, 0.1); color: var(--color-critical); border: 1px solid rgba(244, 63, 94, 0.2); }}
        .severity-badge.high {{ background: rgba(249, 115, 22, 0.1); color: var(--color-high); border: 1px solid rgba(249, 115, 22, 0.2); }}
        .severity-badge.medium {{ background: rgba(234, 179, 8, 0.1); color: var(--color-medium); border: 1px solid rgba(234, 179, 8, 0.2); }}
        .severity-badge.low {{ background: rgba(59, 130, 246, 0.1); color: var(--color-low); border: 1px solid rgba(59, 130, 246, 0.2); }}
        .severity-badge.info {{ background: rgba(16, 185, 129, 0.1); color: var(--color-info); border: 1px solid rgba(16, 185, 129, 0.2); }}

        .collapse-icon {{
            font-size: 12px;
            color: var(--text-muted);
            transition: transform 0.2s ease;
        }}

        .finding-body {{
            padding: 0 24px 20px 24px;
            border-top: 1px solid rgba(255, 255, 255, 0.02);
        }}

        .description {{
            font-size: 14.5px;
            color: var(--text-secondary);
            margin: 16px 0;
        }}

        .flow-box {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 10px;
            padding: 14px 16px;
            margin-bottom: 16px;
        }

        .flow-box h5 {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 10px;
        }

        .flow-box ul {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .flow-box li {
            font-size: 13px;
            color: #dbe4f0;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1.45;
        }

        /* Code box */
        .code-box {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 16px;
            overflow-x: auto;
        }}

        .code-box pre {{
            margin: 0;
        }}

        .code-box code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #e2e8f0;
        }}

        /* Remediation */
        .remediation-box {{
            background-color: rgba(16, 185, 129, 0.03);
            border-left: 3px solid var(--color-info);
            border-radius: 0 8px 8px 0;
            padding: 16px;
            transition: max-height 0.3s ease, padding 0.3s ease;
            overflow: hidden;
        }}

        .remediation-box.collapsed {{
            max-height: 0;
            padding-top: 0;
            padding-bottom: 0;
            border-left-width: 0;
        }}

        .remediation-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}

        .remediation-header h4 {{
            font-size: 12px;
            font-weight: 700;
            color: var(--color-info);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .remediation-box p {{
            font-size: 13.5px;
            color: #cbd5e1;
            line-height: 1.6;
        }}

        .copy-btn {{
            background: none;
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: var(--color-info);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .copy-btn:hover {{
            background: var(--color-info);
            color: var(--bg-primary);
        }}

        /* Sidebar */
        .sidebar-panel {{
            display: flex;
            flex-direction: column;
            gap: 24px;
        }}

        .sidebar-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 20px;
        }}

        .sidebar-card h3 {{
            font-size: 14px;
            font-weight: 700;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 16px;
        }}

        /* Chart */
        .chart-container {{
            position: relative;
            width: 160px;
            height: 160px;
            margin: 0 auto;
        }}

        .donut-chart {{
            width: 100%;
            height: 100%;
        }}

        .chart-segment {{
            transition: stroke-width 0.2s ease;
        }}

        .chart-segment:hover {{
            stroke-width: 12px;
        }}

        .chart-center {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            display: flex;
            flex-direction: column;
        }}

        .chart-center-num {{
            font-size: 24px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1;
        }}

        .chart-center-lbl {{
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
        }}

        /* File Filter List */
        .file-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .file-list-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .file-list-item:hover {{
            border-color: var(--text-muted);
        }}

        .file-list-item.active {{
            background-color: var(--bg-hover);
            border-color: #3b82f6;
            font-weight: 500;
        }}

        .file-count {{
            background-color: rgba(255, 255, 255, 0.05);
            padding: 2px 6px;
            border-radius: 6px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* Checked Rules List */
        .rules-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .rule-item {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 12px;
            opacity: 0.6;
            transition: all 0.2s ease;
        }}

        .rule-item.triggered {{
            opacity: 1;
            border-color: rgba(59, 130, 246, 0.3);
        }}

        .rule-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }}

        .rule-id {{
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: bold;
            color: var(--text-muted);
        }}

        .rule-item.triggered .rule-id {{
            color: #60a5fa;
        }}

        .rule-cnt-badge {{
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
            padding: 1px 6px;
            border-radius: 4px;
            font-weight: bold;
        }}

        .rule-title {{
            font-size: 12px;
            font-weight: 500;
            color: var(--text-secondary);
        }}

        /* Metadata */
        .metadata-card {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .meta-row {{
            display: flex;
            justify-content: space-between;
            font-size: 12px;
        }}

        .meta-row span {{
            color: var(--text-secondary);
        }}

        .meta-row strong {{
            color: var(--text-primary);
        }}

        /* Empty State */
        .empty-state {{
            text-align: center;
            padding: 48px;
            background-color: var(--bg-card);
            border: 1px dashed var(--border-color);
            border-radius: 16px;
        }}

        .empty-icon {{
            font-size: 48px;
            color: var(--color-info);
            margin-bottom: 12px;
        }}

        .empty-state h3 {{
            margin-bottom: 8px;
        }}

        .empty-state p {{
            color: var(--text-secondary);
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <header class="app-header">
        <div class="header-container">
            <div class="logo-section">
                <span class="logo-shield">🛡️</span>
                <div class="logo-text">
                    <h1>SaPyScan</h1>
                    <span class="logo-sub">Static Application Security Testing</span>
                </div>
            </div>
            <div class="target-section">
                <div class="target-meta">
                    <span class="meta-label">TARGET PATH:</span>
                    <span class="meta-value">{target_dir}</span>
                </div>
                <div class="target-meta">
                    <span class="meta-label">SCAN TIME:</span>
                    <span class="meta-value" id="scan-timestamp"></span>
                </div>
            </div>
        </div>
    </header>

    <main class="app-container">
        <!-- Dashboard Stats Row -->
        <div class="stats-row">
            <div class="stat-card total" onclick="setSeverityFilter('ALL')">
                <div class="stat-glow"></div>
                <div class="stat-num" id="stat-total">0</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card critical" onclick="setSeverityFilter('CRITICAL')">
                <div class="stat-glow"></div>
                <div class="stat-num" id="stat-critical">0</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high" onclick="setSeverityFilter('HIGH')">
                <div class="stat-glow"></div>
                <div class="stat-num" id="stat-high">0</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium" onclick="setSeverityFilter('MEDIUM')">
                <div class="stat-glow"></div>
                <div class="stat-num" id="stat-medium">0</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low" onclick="setSeverityFilter('LOW')">
                <div class="stat-glow"></div>
                <div class="stat-num" id="stat-low">0</div>
                <div class="stat-label">Low & Info</div>
            </div>
        </div>

        <!-- Main Workspace -->
        <div class="workspace">
            <!-- Left Panel: Findings & Controls -->
            <section class="findings-panel">
                <div class="controls-card">
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" id="search-input" placeholder="Search by file, rule ID, description..." oninput="handleSearch(this.value)">
                        <button class="clear-search" id="clear-search-btn" onclick="clearSearch()" style="display: none;">✕</button>
                    </div>
                    
                    <div class="filter-tabs">
                        <button class="tab-btn active" id="tab-all" onclick="setSeverityFilter('ALL')">All</button>
                        <button class="tab-btn" id="tab-critical" onclick="setSeverityFilter('CRITICAL')">Critical <span class="tab-badge" id="badge-critical">0</span></button>
                        <button class="tab-btn" id="tab-high" onclick="setSeverityFilter('HIGH')">High <span class="tab-badge" id="badge-high">0</span></button>
                        <button class="tab-btn" id="tab-medium" onclick="setSeverityFilter('MEDIUM')">Medium <span class="tab-badge" id="badge-medium">0</span></button>
                        <button class="tab-btn" id="tab-low" onclick="setSeverityFilter('LOW')">Low & Info <span class="tab-badge" id="badge-low">0</span></button>
                    </div>
                </div>

                <div id="findings-list" class="findings-list">
                    <!-- Dynamic rendering -->
                </div>
            </section>

            <!-- Right Panel: Sidebar Charts & Lists -->
            <aside class="sidebar-panel">
                <!-- Severity Distribution Chart -->
                <div class="sidebar-card">
                    <h3>Severity Distribution</h3>
                    <div class="chart-container">
                        <svg id="donut-chart" viewBox="0 0 100 100" class="donut-chart">
                            <!-- JS will generate this -->
                        </svg>
                        <div class="chart-center">
                            <span class="chart-center-num" id="chart-total-num">0</span>
                            <span class="chart-center-lbl">Issues</span>
                        </div>
                    </div>
                </div>

                <!-- File Filter List -->
                <div class="sidebar-card">
                    <h3>Vulnerable Files</h3>
                    <div class="file-list" id="file-filter-list">
                        <!-- JS will populate -->
                    </div>
                </div>

                <!-- Rules Checked Card -->
                <div class="sidebar-card">
                    <h3>Checked Rules</h3>
                    <div class="rules-list" id="checked-rules-list">
                        <!-- JS will populate -->
                    </div>
                </div>

                <!-- Engine details -->
                <div class="sidebar-card metadata-card">
                    <h3>Scanner Metadata</h3>
                    <div class="meta-row">
                        <span>Engine Version</span>
                        <strong>v1.1.0</strong>
                    </div>
                    <div class="meta-row">
                        <span>Analysis Base</span>
                        <strong>Python AST parser</strong>
                    </div>
                    <div class="meta-row">
                        <span>Total Rules</span>
                        <strong id="meta-total-rules">14</strong>
                    </div>
                </div>
            </aside>
        </div>
    </main>

    <script>
        const findingsData = {findings_json};
        
        const state = {{
            severityFilter: 'ALL',
            fileFilter: null,
            searchQuery: ''
        }};

        document.addEventListener('DOMContentLoaded', () => {{
            document.getElementById('scan-timestamp').innerText = new Date().toLocaleString();
            
            calculateStats();
            renderCheckedRules();
            renderFileFilterList();
            renderFindings();
            renderDonutChart();
        }});

        function calculateStats() {{
            const counts = {{ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }};
            findingsData.forEach(f => {{
                const sev = f.severity.toUpperCase();
                if (counts[sev] !== undefined) {{
                    counts[sev]++;
                }} else {{
                    counts.INFO++;
                }}
            }});

            document.getElementById('stat-total').innerText = findingsData.length;
            document.getElementById('stat-critical').innerText = counts.CRITICAL;
            document.getElementById('stat-high').innerText = counts.HIGH;
            document.getElementById('stat-medium').innerText = counts.MEDIUM;
            document.getElementById('stat-low').innerText = counts.LOW + counts.INFO;

            document.getElementById('badge-critical').innerText = counts.CRITICAL;
            document.getElementById('badge-high').innerText = counts.HIGH;
            document.getElementById('badge-medium').innerText = counts.MEDIUM;
            document.getElementById('badge-low').innerText = counts.LOW + counts.INFO;
        }}

        function renderDonutChart() {{
            const svg = document.getElementById('donut-chart');
            svg.innerHTML = '';
            
            const counts = {{ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }};
            findingsData.forEach(f => {{
                const sev = f.severity.toUpperCase();
                if (counts[sev] !== undefined) {{
                    counts[sev]++;
                }} else {{
                    counts.INFO++;
                }}
            }});
            
            const lowAndInfo = counts.LOW + counts.INFO;
            const segments = [
                {{ key: 'CRITICAL', val: counts.CRITICAL, color: '#f43f5e' }},
                {{ key: 'HIGH', val: counts.HIGH, color: '#f97316' }},
                {{ key: 'MEDIUM', val: counts.MEDIUM, color: '#eab308' }},
                {{ key: 'LOW', val: lowAndInfo, color: '#3b82f6' }}
            ].filter(s => s.val > 0);

            const total = segments.reduce((sum, s) => sum + s.val, 0);
            document.getElementById('chart-total-num').innerText = total;

            if (total === 0) {{
                const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                circle.setAttribute('cx', '50');
                circle.setAttribute('cy', '50');
                circle.setAttribute('r', '35');
                circle.setAttribute('fill', 'none');
                circle.setAttribute('stroke', '#1e293b');
                circle.setAttribute('stroke-width', '10');
                svg.appendChild(circle);
                return;
            }}

            const r = 35;
            const circumference = 2 * Math.PI * r;
            let accumulatedOffset = 0;

            segments.forEach(seg => {{
                const percentage = seg.val / total;
                const dashArray = `${{percentage * circumference}} ${{circumference}}`;
                const dashOffset = -accumulatedOffset;

                const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                circle.setAttribute('cx', '50');
                circle.setAttribute('cy', '50');
                circle.setAttribute('r', r.toString());
                circle.setAttribute('fill', 'none');
                circle.setAttribute('stroke', seg.color);
                circle.setAttribute('stroke-width', '10');
                circle.setAttribute('stroke-dasharray', dashArray);
                circle.setAttribute('stroke-dashoffset', dashOffset.toString());
                circle.setAttribute('transform', 'rotate(-90 50 50)');
                circle.setAttribute('class', 'chart-segment');
                
                const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
                title.textContent = `${{seg.key}}: ${{seg.val}} (${{Math.round(percentage * 100)}}%)`;
                circle.appendChild(title);
                
                svg.appendChild(circle);
                accumulatedOffset += percentage * circumference;
            }});
        }}

        function getFilteredFindings() {{
            return findingsData.filter(f => {{
                if (state.severityFilter !== 'ALL') {{
                    if (state.severityFilter === 'LOW') {{
                        if (f.severity !== 'LOW' && f.severity !== 'INFO') return false;
                    }} else if (f.severity.toUpperCase() !== state.severityFilter) {{
                        return false;
                    }}
                }}
                
                if (state.fileFilter) {{
                    const displayPath = f.relative_path || f.file_path.replace(/\\\\/g, '/').split('/').pop();
                    if (displayPath !== state.fileFilter) return false;
                }}

                if (state.searchQuery) {{
                    const q = state.searchQuery.toLowerCase();
                    const title = (f.title || '').toLowerCase();
                    const desc = (f.description || '').toLowerCase();
                    const rule = (f.rule_id || '').toLowerCase();
                    const file = (f.file_path || '').toLowerCase();
                    const snippet = (f.code_snippet || '').toLowerCase();
                    if (!title.includes(q) && !desc.includes(q) && !rule.includes(q) && !file.includes(q) && !snippet.includes(q)) {{
                        return false;
                    }}
                }}

                return true;
            }});
        }}

        function renderFindings() {{
            const list = document.getElementById('findings-list');
            list.innerHTML = '';
            
            const filtered = getFilteredFindings();
            
            if (filtered.length === 0) {{
                list.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">✓</div>
                        <h3>No findings match active filters</h3>
                        <p>Try clearing filters or search terms.</p>
                    </div>
                `;
                return;
            }}

            filtered.forEach((f, idx) => {{
                const escapedSnippet = f.code_snippet ? f.code_snippet.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;") : '';
                const codeHtml = escapedSnippet ? `<div class="code-box"><pre><code>${{escapedSnippet}}</code></pre></div>` : '';
                const flowItems = Array.isArray(f.data_flow) ? f.data_flow : [];
                const flowHtml = flowItems.length ? `
                    <div class="flow-box">
                        <h5>Data Flow</h5>
                        <ul>${{flowItems.map(step => `<li>${{step}}</li>`).join('')}}</ul>
                    </div>
                ` : '';
                const assessment = (f.assessment || 'needs_review').toLowerCase();
                
                const displayPath = f.relative_path || f.file_path.replace(/\\\\/g, '/').split('/').pop();
                
                const card = document.createElement('div');
                card.className = `finding-card border-${{f.severity.toLowerCase()}}`;
                card.innerHTML = `
                    <div class="finding-header" onclick="toggleRemediation(${{idx}})">
                        <div class="finding-title-group">
                            <div class="finding-title">${{f.title}}</div>
                            <div class="finding-sub">
                                <span class="finding-rule">${{f.rule_id}}</span>
                                <span class="finding-loc">📄 ${{displayPath}}:${{f.line_no}}</span>
                            </div>
                        </div>
                        <div class="header-right">
                            <span class="assessment-badge ${{assessment}}">${{assessment.replace(/_/g, ' ')}}</span>
                            <span class="severity-badge ${{f.severity.toLowerCase()}}">${{f.severity}}</span>
                            <span class="collapse-icon" id="collapse-icon-${{idx}}">▼</span>
                        </div>
                    </div>
                    <div class="finding-body">
                        <div class="description">${{f.description}}</div>
                        ${{flowHtml}}
                        ${{codeHtml}}
                        <div class="remediation-box collapsed" id="remediation-${{idx}}">
                            <div class="remediation-header">
                                <h4>Remediation Guideline</h4>
                                <button class="copy-btn" onclick="copyFindingDetails(${{idx}}, event)">Copy Details</button>
                            </div>
                            <p>${{f.remediation}}</p>
                        </div>
                    </div>
                `;
                list.appendChild(card);
            }});
        }}

        function toggleRemediation(idx) {{
            const box = document.getElementById(`remediation-${{idx}}`);
            const icon = document.getElementById(`collapse-icon-${{idx}}`);
            if (box.classList.contains('collapsed')) {{
                box.classList.remove('collapsed');
                icon.innerText = '▲';
            }} else {{
                box.classList.add('collapsed');
                icon.innerText = '▼';
            }}
        }}

        function copyFindingDetails(idx, event) {{
            event.stopPropagation();
            const filtered = getFilteredFindings();
            const f = filtered[idx];
            const flow = Array.isArray(f.data_flow) && f.data_flow.length ? `
Data Flow:
- ${{f.data_flow.join('\n- ')}}` : '';
            const text = `Vulnerability: ${{f.title}} (${{f.rule_id}})
Severity: ${{f.severity}}
Location: ${{f.file_path}}:${{f.line_no}}
Description: ${{f.description}}
Assessment: ${{f.assessment || 'needs_review'}}${{flow}}
Remediation: ${{f.remediation}}`;

            navigator.clipboard.writeText(text).then(() => {{
                const btn = event.target;
                const originalText = btn.innerText;
                btn.innerText = 'Copied!';
                btn.style.background = '#10b981';
                setTimeout(() => {{
                    btn.innerText = originalText;
                    btn.style.background = '';
                }}, 1500);
            }});
        }}

        function renderFileFilterList() {{
            const container = document.getElementById('file-filter-list');
            container.innerHTML = '';
            
            const fileCounts = {{}};
            findingsData.forEach(f => {{
                const displayPath = f.relative_path || f.file_path.replace(/\\\\/g, '/').split('/').pop();
                fileCounts[displayPath] = (fileCounts[displayPath] || 0) + 1;
            }});

            const allItem = document.createElement('div');
            allItem.className = `file-list-item ${{state.fileFilter === null ? 'active' : ''}}`;
            allItem.onclick = () => selectFile(null);
            allItem.innerHTML = `<span>All Files</span> <span class="file-count">${{findingsData.length}}</span>`;
            container.appendChild(allItem);

            Object.keys(fileCounts).sort((a, b) => fileCounts[b] - fileCounts[a]).forEach(file => {{
                const item = document.createElement('div');
                item.className = `file-list-item ${{state.fileFilter === file ? 'active' : ''}}`;
                item.onclick = () => selectFile(file);
                item.innerHTML = `<span>${{file}}</span> <span class="file-count">${{fileCounts[file]}}</span>`;
                container.appendChild(item);
            }});
        }}

        function selectFile(file) {{
            state.fileFilter = file;
            renderFileFilterList();
            renderFindings();
        }}

        function renderCheckedRules() {{
            const container = document.getElementById('checked-rules-list');
            container.innerHTML = '';
            
            const ruleCounts = {{}};
            findingsData.forEach(f => {{
                ruleCounts[f.title] = (ruleCounts[f.title] || 0) + 1;
            }});

            const knownRules = [
                {{ id: "OWASP_A01_2021_PATH", title: "Potential Path Traversal" }},
                {{ id: "OWASP_A02_2021_HASH", title: "Use of Weak Cryptographic Hash Function" }},
                {{ id: "OWASP_A02_2021_CIPHER", title: "Use of Weak Cryptographic Cipher" }},
                {{ id: "OWASP_A03_2021_SQLI", title: "Potential SQL Injection" }},
                {{ id: "OWASP_A03_2021_CMD", title: "Potential Command Injection" }},
                {{ id: "OWASP_A03_2021_XSS", title: "Reflected XSS / Insecure HTTP Response" }},
                {{ id: "OWASP_A03_2021_EVAL", title: "Dangerous Use of eval/exec" }},
                {{ id: "OWASP_A04_2021_RANDOM", title: "Use of Weak Pseudo-Random Number Generator" }},
                {{ id: "OWASP_A05_2021_SSL", title: "Insecure SSL/TLS Configuration" }},
                {{ id: "OWASP_A05_2021_DEBUG", title: "Flask Debug Mode Enabled" }},
                {{ id: "OWASP_A07_2021_SECRET", title: "Hardcoded Password / Key Detected" }},
                {{ id: "OWASP_A07_2021_ASSERT", title: "Use of assert for Security Check" }},
                {{ id: "OWASP_A08_2021_DESERIAL", title: "Insecure Deserialization Detected" }},
                {{ id: "OWASP_A10_2021_SSRF", title: "Potential Server-Side Request Forgery" }}
            ];

            knownRules.forEach(rule => {{
                const cnt = ruleCounts[rule.title] || 0;
                const item = document.createElement('div');
                item.className = `rule-item ${{cnt > 0 ? 'triggered' : ''}}`;
                item.innerHTML = `
                    <div class="rule-header">
                        <span class="rule-id">${{rule.id}}</span>
                        <span class="rule-cnt-badge" style="background: ${{cnt > 0 ? '#1e293b' : '#0f172a'}}; color: ${{cnt > 0 ? '#3b82f6' : '#4b5563'}}">${{cnt}}</span>
                    </div>
                    <div class="rule-title">${{rule.title}}</div>
                `;
                container.appendChild(item);
            }});
        }}

        function setSeverityFilter(sev) {{
            state.severityFilter = sev;
            
            const tabs = ['all', 'critical', 'high', 'medium', 'low'];
            tabs.forEach(t => {{
                const btn = document.getElementById(`tab-${{t}}`);
                if (t === sev.toLowerCase()) {{
                    btn.classList.add('active');
                }} else {{
                    btn.classList.remove('active');
                }}
            }});

            renderFindings();
        }}

        function handleSearch(val) {{
            state.searchQuery = val;
            const clearBtn = document.getElementById('clear-search-btn');
            if (val) {{
                clearBtn.style.display = 'block';
            }} else {{
                clearBtn.style.display = 'none';
            }}
            renderFindings();
        }}

        function clearSearch() {{
            document.getElementById('search-input').value = '';
            handleSearch('');
        }}
    </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
