import os
from typing import List, Dict, Any
from .rules import ALL_RULES

class ReportGenerator:
    @staticmethod
    def render_html(results: List[Dict[str, Any]], target_dir: str, output_path: str):
        # Count statistics
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        rule_counts = {}
        
        for vuln in results:
            sev = vuln.get("severity", "INFO").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            rule_title = vuln.get("title", "Unknown Rule")
            rule_counts[rule_title] = rule_counts.get(rule_title, 0) + 1

        # Pre-render parts of the HTML to avoid complex f-string brace nesting issues
        empty_state_html = ""
        if not results:
            empty_state_html = """
            <div class="empty-state">
                <div class="empty-icon">✓</div>
                <h3>No Vulnerabilities Found!</h3>
                <p>PyShield-SAST didn't find any common static vulnerabilities in this codebase.</p>
            </div>
            """

        findings_html_list = []
        for vuln in results:
            code_sec = ""
            if vuln.get("code_snippet"):
                # Escape HTML tags inside code snippet to avoid rendering issues
                escaped_snippet = vuln.get("code_snippet").replace("<", "&lt;").replace(">", "&gt;")
                code_sec = f'<div class="code-box">{escaped_snippet}</div>'
            
            findings_html_list.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title-group">
                        <div class="finding-title">{vuln.get("title")}</div>
                        <div class="finding-rule">{vuln.get("rule_id")}</div>
                    </div>
                    <span class="severity-badge {vuln.get("severity").lower()}">{vuln.get("severity")}</span>
                </div>
                <div class="finding-body">
                    <div class="location">
                        <span>📄</span> {os.path.basename(vuln.get("file_path"))}:{vuln.get("line_no")}
                    </div>
                    <div class="description">
                        {vuln.get("description")}
                    </div>
                    
                    {code_sec}
                    
                    <div class="remediation-box">
                        <h4>Remediation Guideline</h4>
                        <p>{vuln.get("remediation")}</p>
                    </div>
                </div>
            </div>
            """)
        findings_html = "\n".join(findings_html_list)

        rules_html_list = []
        for r_title, r_cnt in rule_counts.items():
            rules_html_list.append(f"""
            <div class="rule-breakdown-item">
                <span class="rule-name" title="{r_title}">{r_title}</span>
                <span class="rule-count">{r_cnt}</span>
            </div>
            """)
        rules_html = "\n".join(rules_html_list)
        if not rule_counts:
            rules_html = '<div style="color:var(--text-secondary); font-size:13px;">No rules triggered.</div>'

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyShield-SAST Security Vulnerability Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0b0f19;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-critical: #ef4444;
            --accent-high: #f97316;
            --accent-medium: #eab308;
            --accent-low: #3b82f6;
            --accent-info: #10b981;
            --border-color: #374151;
            --glow-color: rgba(59, 130, 246, 0.15);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Plus Jakarta Sans', sans-serif;
            line-height: 1.6;
            padding-bottom: 60px;
        }}

        header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 40px 20px;
            position: relative;
            overflow: hidden;
        }}

        header::after {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--accent-critical), var(--accent-high), var(--accent-medium), var(--accent-low));
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }}

        .logo-area {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 10px;
        }}

        .logo-badge {{
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            padding: 6px 12px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 1px;
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.4);
        }}

        h1 {{
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(to right, #ffffff, #93c5fd);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .meta-text {{
            color: var(--text-secondary);
            font-size: 14px;
            margin-top: 5px;
        }}

        .meta-text span {{
            color: var(--text-primary);
            font-weight: 500;
        }}

        /* Metrics / Summary Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }}

        .metric-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }}

        .metric-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
            border-color: #4b5563;
        }}

        .metric-value {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 5px;
        }}

        .metric-label {{
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}

        .metric-card.critical {{ border-top: 4px solid var(--accent-critical); }}
        .metric-card.high {{ border-top: 4px solid var(--accent-high); }}
        .metric-card.medium {{ border-top: 4px solid var(--accent-medium); }}
        .metric-card.low {{ border-top: 4px solid var(--accent-low); }}
        .metric-card.total {{ border-top: 4px solid #8b5cf6; }}

        .metric-card.critical .metric-value {{ color: var(--accent-critical); }}
        .metric-card.high .metric-value {{ color: var(--accent-high); }}
        .metric-card.medium .metric-value {{ color: var(--accent-medium); }}
        .metric-card.low .metric-value {{ color: var(--accent-low); }}

        /* Main Section layout */
        .main-layout {{
            margin-top: 40px;
            display: grid;
            grid-template-columns: 3fr 1fr;
            gap: 30px;
        }}

        @media (max-width: 900px) {{
            .main-layout {{
                grid-template-columns: 1fr;
            }}
        }}

        .findings-container {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}

        .sidebar {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}

        .section-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        /* Finding Card styling */
        .finding-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.3s ease;
        }}

        .finding-card:hover {{
            border-color: #6b7280;
        }}

        .finding-header {{
            padding: 18px 24px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 15px;
            border-bottom: 1px solid var(--border-color);
            background-color: rgba(255, 255, 255, 0.01);
        }}

        .finding-title-group {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .finding-title {{
            font-size: 16px;
            font-weight: 600;
        }}

        .finding-rule {{
            font-size: 11px;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 2px 6px;
            border-radius: 4px;
            align-self: flex-start;
        }}

        .severity-badge {{
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-badge.critical {{ background-color: rgba(239, 68, 68, 0.15); color: var(--accent-critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .severity-badge.high {{ background-color: rgba(249, 115, 22, 0.15); color: var(--accent-high); border: 1px solid rgba(249, 115, 22, 0.3); }}
        .severity-badge.medium {{ background-color: rgba(234, 179, 8, 0.15); color: var(--accent-medium); border: 1px solid rgba(234, 179, 8, 0.3); }}
        .severity-badge.low {{ background-color: rgba(59, 130, 246, 0.15); color: var(--accent-low); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .severity-badge.info {{ background-color: rgba(16, 185, 129, 0.15); color: var(--accent-info); border: 1px solid rgba(16, 185, 129, 0.3); }}

        .finding-body {{
            padding: 20px 24px;
        }}

        .location {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #93c5fd;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .description {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 20px;
        }}

        /* Code box */
        .code-box {{
            background-color: var(--bg-primary);
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 12px 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #e5e7eb;
            overflow-x: auto;
            margin-bottom: 20px;
            position: relative;
        }}

        .code-box::before {{
            content: "CODE SNIPPET";
            position: absolute;
            top: 4px;
            right: 8px;
            font-size: 9px;
            color: #4b5563;
            letter-spacing: 0.5px;
            font-weight: bold;
        }}

        /* Remediation Alert Box */
        .remediation-box {{
            background-color: rgba(16, 185, 129, 0.05);
            border-left: 4px solid var(--accent-info);
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
        }}

        .remediation-box h4 {{
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-info);
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .remediation-box p {{
            font-size: 13.5px;
            color: #d1d5db;
        }}

        /* Empty state styling */
        .empty-state {{
            background-color: var(--bg-secondary);
            border: 1px dashed var(--border-color);
            border-radius: 12px;
            padding: 60px 20px;
            text-align: center;
            color: var(--text-secondary);
        }}

        .empty-icon {{
            font-size: 48px;
            margin-bottom: 15px;
            color: var(--accent-info);
        }}

        /* Card Widgets */
        .card-widget {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }}

        .rules-breakdown-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .rule-breakdown-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
        }}

        .rule-name {{
            color: var(--text-secondary);
            max-width: 75%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .rule-count {{
            font-weight: 600;
            background-color: var(--border-color);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
        }}
    </style>
</head>
<body>

    <header>
        <div class="container">
            <div class="logo-area">
                <div class="logo-badge">SEC SAST</div>
                <h1>PyShield Security Scan Report</h1>
            </div>
            <p class="meta-text">Target Directory: <span>{os.path.basename(target_dir)}</span></p>
            <p class="meta-text">Scan Path: <span style="font-family: 'JetBrains Mono', monospace; font-size:12px;">{target_dir}</span></p>
        </div>
    </header>

    <div class="container">
        <!-- Summary Stats Cards -->
        <div class="metrics-grid">
            <div class="metric-card total">
                <div class="metric-value">{len(results)}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-value">{severity_counts.get("CRITICAL", 0)}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric-card high">
                <div class="metric-value">{severity_counts.get("HIGH", 0)}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric-card medium">
                <div class="metric-value">{severity_counts.get("MEDIUM", 0)}</div>
                <div class="metric-label">Medium</div>
            </div>
            <div class="metric-card low">
                <div class="metric-value">{severity_counts.get("LOW", 0) + severity_counts.get("INFO", 0)}</div>
                <div class="metric-label">Low & Info</div>
            </div>
        </div>

        <div class="main-layout">
            <!-- Findings List -->
            <div>
                <h3 class="section-title">Scan Findings ({len(results)})</h3>
                <div class="findings-container">
                    {empty_state_html}
                    {findings_html}
                </div>
            </div>

            <!-- Sidebar -->
            <div class="sidebar">
                <div class="card-widget">
                    <h3 class="section-title" style="margin-bottom: 12px;">Rule Breakdown</h3>
                    <div class="rules-breakdown-list">
                        {rules_html}
                    </div>
                </div>
                
                <div class="card-widget">
                    <h3 class="section-title" style="margin-bottom: 12px;">Scan Details</h3>
                    <div style="font-size: 13px; color: var(--text-secondary); display: flex; flex-direction: column; gap: 8px;">
                        <div>Scanner Engine: <strong>PyShield SAST v1.0.0</strong></div>
                        <div>Target Platform: <strong>Python AST Engine</strong></div>
                        <div>Checked Rules: <strong>{len(ALL_RULES)} active rules</strong></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
