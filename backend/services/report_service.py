"""
Report Export Service - Generate Detailed Excel, PDF, and XML reports (Checkmarx-style)
Includes: SAST, SCA, Secrets Detection, Threat Model (STRIDE), and MITRE ATT&CK Mapping
"""
from typing import List, Dict, Any, Tuple
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from collections import defaultdict
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.chart import PieChart, BarChart, Reference
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from io import BytesIO

class ReportService:
    """Service for generating detailed security reports in Checkmarx style"""

    # Severity colors
    SEVERITY_COLORS = {
        'critical': 'C00000',  # Dark Red
        'high': 'FF0000',      # Red
        'medium': 'FFA500',    # Orange
        'low': 'FFFF00',       # Yellow
        'info': '92D050'       # Green
    }

    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

    def generate_excel_report(self, scan_data: Dict[str, Any], output_path: str = None) -> BytesIO:
        """
        Generate comprehensive Excel report with multiple detailed sheets (Checkmarx-style)

        Sheets:
        1. Cover Page - Project metadata and branding
        2. Dashboard - Visual summary with statistics
        3. Overall Summary - Aggregated findings across all scan types
        4-7. SAST Findings by Severity (Critical, High, Medium, Low)
        8. SAST - Grouped by CWE
        9. SAST - Grouped by OWASP Category
        10. SAST - Grouped by File
        11-14. SCA Findings by Severity (Critical, High, Medium, Low)
        15. SCA - Grouped by Package
        16. SCA - CVE Details
        17. Secrets Detection - All findings
        18. Threat Model - STRIDE Analysis
        19. MITRE ATT&CK Mapping
        20. Remediation Summary - Consolidated recommendations
        """
        wb = Workbook()
        wb.remove(wb.active)  # Remove default sheet

        # Common styles
        styles = self._create_styles()

        # Sheet 1: Cover Page
        self._create_cover_page(wb, scan_data, styles)

        # Sheet 2: Dashboard
        self._create_dashboard_sheet(wb, scan_data, styles)

        # Sheet 3: Overall Summary
        self._create_overall_summary_sheet(wb, scan_data, styles)

        # SAST Findings - Detailed sheets by severity
        sast_findings = scan_data.get('sast_findings', [])
        if sast_findings:
            for severity in self.SEVERITY_ORDER:
                findings = [f for f in sast_findings if f.get('severity', '').lower() == severity]
                if findings:
                    self._create_sast_detailed_sheet(wb, findings, severity, styles)

            # SAST - Grouped views
            self._create_sast_by_cwe_sheet(wb, sast_findings, styles)
            self._create_sast_by_owasp_sheet(wb, sast_findings, styles)
            self._create_sast_by_file_sheet(wb, sast_findings, styles)

        # SCA Findings - Detailed sheets by severity
        sca_findings = scan_data.get('sca_findings', [])
        if sca_findings:
            for severity in self.SEVERITY_ORDER:
                findings = [f for f in sca_findings if f.get('severity', '').lower() == severity]
                if findings:
                    self._create_sca_detailed_sheet(wb, findings, severity, styles)

            # SCA - Grouped views
            self._create_sca_by_package_sheet(wb, sca_findings, styles)
            self._create_sca_cve_details_sheet(wb, sca_findings, styles)

        # Secrets Detection
        secret_findings = scan_data.get('secret_findings', [])
        if secret_findings:
            self._create_secrets_detailed_sheet(wb, secret_findings, styles)

        # Threat Model (STRIDE)
        threat_model = scan_data.get('threat_model', {})
        if threat_model:
            self._create_threat_model_sheet(wb, threat_model, styles)
            self._create_mitre_attack_sheet(wb, threat_model, styles)

        # Remediation Summary
        self._create_remediation_summary_sheet(wb, scan_data, styles)

        # Save or return
        if output_path:
            wb.save(output_path)
            return output_path
        else:
            buffer = BytesIO()
            wb.save(buffer)
            buffer.seek(0)
            return buffer

    def _create_styles(self) -> Dict[str, Any]:
        """Create common styles for Excel sheets"""
        return {
            'header_fill': PatternFill(start_color="366092", end_color="366092", fill_type="solid"),
            'header_font': Font(color="FFFFFF", bold=True, size=12),
            'title_font': Font(bold=True, size=20, color="366092"),
            'subtitle_font': Font(bold=True, size=14, color="366092"),
            'bold_font': Font(bold=True),
            'border': Border(
                left=Side(style='thin'),
                right=Side(style='thin'),
                top=Side(style='thin'),
                bottom=Side(style='thin')
            ),
            'center_align': Alignment(horizontal='center', vertical='center', wrap_text=True),
            'left_align': Alignment(horizontal='left', vertical='top', wrap_text=True),
        }

    def _create_cover_page(self, wb: Workbook, scan_data: Dict[str, Any], styles: Dict):
        """Create cover page with project metadata"""
        ws = wb.create_sheet("Cover Page")

        # Title
        ws['B2'] = "Application Security Scan Report"
        ws['B2'].font = Font(bold=True, size=24, color="366092")
        ws.merge_cells('B2:G2')
        ws['B2'].alignment = Alignment(horizontal='center', vertical='center')

        # Subtitle
        ws['B4'] = "Detailed Security Analysis Report"
        ws['B4'].font = Font(size=14, color="666666")
        ws.merge_cells('B4:G4')
        ws['B4'].alignment = Alignment(horizontal='center')

        # Project Information
        row = 7
        metadata = [
            ('Project Name:', scan_data.get('project_name', 'Unknown')),
            ('Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ('Scan Types:', ', '.join(scan_data.get('scan_types', []))),
            ('Total Findings:', str(self._get_total_findings(scan_data))),
        ]

        for label, value in metadata:
            ws[f'B{row}'] = label
            ws[f'B{row}'].font = styles['bold_font']
            ws[f'D{row}'] = value
            row += 1

        # Severity Summary
        row += 2
        ws[f'B{row}'] = "Severity Distribution"
        ws[f'B{row}'].font = styles['subtitle_font']
        row += 1

        severity_counts = self._count_all_severities(scan_data)
        for severity in self.SEVERITY_ORDER:
            count = severity_counts.get(severity, 0)
            if count > 0:
                ws[f'B{row}'] = severity.upper()
                ws[f'D{row}'] = count
                ws[f'B{row}'].fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                  end_color=self.SEVERITY_COLORS[severity],
                                                  fill_type="solid")
                if severity in ['critical', 'high']:
                    ws[f'B{row}'].font = Font(color="FFFFFF", bold=True)
                row += 1

        # Column widths
        ws.column_dimensions['B'].width = 25
        ws.column_dimensions['D'].width = 30

    def _create_dashboard_sheet(self, wb: Workbook, scan_data: Dict[str, Any], styles: Dict):
        """Create dashboard with summary statistics"""
        ws = wb.create_sheet("Dashboard")

        # Title
        ws['A1'] = "Security Scan Dashboard"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:H1')

        # Overall Statistics
        row = 3
        ws[f'A{row}'] = "Overall Statistics"
        ws[f'A{row}'].font = styles['subtitle_font']
        row += 1

        # Headers
        headers = ['Metric', 'Value']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        # Metrics
        sast_findings = scan_data.get('sast_findings', [])
        sca_findings = scan_data.get('sca_findings', [])
        secret_findings = scan_data.get('secret_findings', [])

        metrics = [
            ('Total Vulnerabilities', self._get_total_findings(scan_data)),
            ('SAST Findings', len(sast_findings)),
            ('SCA Findings', len(sca_findings)),
            ('Secrets Detected', len(secret_findings)),
            ('Files Scanned', len(set([f.get('file_path', '') for f in sast_findings + secret_findings]))),
            ('Unique CWEs', len(set([f.get('cwe_id', '') for f in sast_findings if f.get('cwe_id')]))),
            ('Unique CVEs', len(set([f.get('cve', '') for f in sca_findings if f.get('cve')]))),
        ]

        for metric, value in metrics:
            ws.cell(row, 1, metric)
            ws.cell(row, 2, value)
            row += 1

        # Severity Distribution Table
        row += 2
        ws[f'A{row}'] = "Severity Distribution"
        ws[f'A{row}'].font = styles['subtitle_font']
        row += 1

        headers = ['Severity', 'SAST', 'SCA', 'Secrets', 'Total', 'Percentage']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        sast_severity = self._count_by_severity(sast_findings)
        sca_severity = self._count_by_severity(sca_findings)
        secret_severity = self._count_by_severity(secret_findings)
        total_findings = self._get_total_findings(scan_data)

        for severity in self.SEVERITY_ORDER:
            sast_count = sast_severity.get(severity, 0)
            sca_count = sca_severity.get(severity, 0)
            secret_count = secret_severity.get(severity, 0)
            total = sast_count + sca_count + secret_count
            percentage = (total / total_findings * 100) if total_findings > 0 else 0

            ws.cell(row, 1, severity.upper())
            ws.cell(row, 2, sast_count)
            ws.cell(row, 3, sca_count)
            ws.cell(row, 4, secret_count)
            ws.cell(row, 5, total)
            ws.cell(row, 6, f"{percentage:.1f}%")

            # Color code severity column
            severity_cell = ws.cell(row, 1)
            severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                            end_color=self.SEVERITY_COLORS[severity],
                                            fill_type="solid")
            if severity in ['critical', 'high']:
                severity_cell.font = Font(color="FFFFFF", bold=True)

            row += 1

        # Auto-size columns
        for col in range(1, 9):
            ws.column_dimensions[get_column_letter(col)].width = 18

    def _create_overall_summary_sheet(self, wb: Workbook, scan_data: Dict[str, Any], styles: Dict):
        """Create overall summary sheet with aggregated findings"""
        ws = wb.create_sheet("Overall Summary")

        # Title
        ws['A1'] = "Overall Security Summary"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:J1')

        # Scan Information
        row = 3
        scan_info = [
            ('Project:', scan_data.get('project_name', 'Unknown')),
            ('Scan Date:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ('Scan Types:', ', '.join(scan_data.get('scan_types', []))),
        ]

        for label, value in scan_info:
            ws[f'A{row}'] = label
            ws[f'A{row}'].font = styles['bold_font']
            ws[f'B{row}'] = value
            ws.merge_cells(f'B{row}:D{row}')
            row += 1

        # Summary Table
        row += 2
        ws[f'A{row}'] = "Findings Summary by Scan Type and Severity"
        ws[f'A{row}'].font = styles['subtitle_font']
        ws.merge_cells(f'A{row}:J{row}')
        row += 1

        headers = ['Scan Type', 'Total', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Risk Score']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']
            cell.alignment = styles['center_align']

        row += 1

        # Data rows
        scan_types_data = [
            ('SAST (Code Vulnerabilities)', scan_data.get('sast_findings', [])),
            ('SCA (Dependencies)', scan_data.get('sca_findings', [])),
            ('Secrets Detection', scan_data.get('secret_findings', [])),
        ]

        for scan_type, findings in scan_types_data:
            if findings:
                severity_counts = self._count_by_severity(findings)
                risk_score = self._calculate_risk_score(severity_counts)

                ws.cell(row, 1, scan_type)
                ws.cell(row, 2, len(findings))
                ws.cell(row, 3, severity_counts.get('critical', 0))
                ws.cell(row, 4, severity_counts.get('high', 0))
                ws.cell(row, 5, severity_counts.get('medium', 0))
                ws.cell(row, 6, severity_counts.get('low', 0))
                ws.cell(row, 7, severity_counts.get('info', 0))
                ws.cell(row, 8, f"{risk_score:.1f}")

                row += 1

        # Total row
        total_severity = self._count_all_severities(scan_data)
        total_risk = self._calculate_risk_score(total_severity)

        ws.cell(row, 1, 'TOTAL')
        ws.cell(row, 1).font = styles['bold_font']
        ws.cell(row, 2, self._get_total_findings(scan_data))
        ws.cell(row, 3, total_severity.get('critical', 0))
        ws.cell(row, 4, total_severity.get('high', 0))
        ws.cell(row, 5, total_severity.get('medium', 0))
        ws.cell(row, 6, total_severity.get('low', 0))
        ws.cell(row, 7, total_severity.get('info', 0))
        ws.cell(row, 8, f"{total_risk:.1f}")

        # Bold total row
        for col in range(1, 9):
            ws.cell(row, col).font = styles['bold_font']

        # Top Issues Section
        row += 3
        ws[f'A{row}'] = "Top 10 Critical Issues Requiring Immediate Attention"
        ws[f'A{row}'].font = styles['subtitle_font']
        ws.merge_cells(f'A{row}:J{row}')
        row += 1

        headers = ['#', 'Type', 'Severity', 'Title', 'File/Package', 'Line/Version', 'CWE/CVE', 'CVSS']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        # Get top critical/high findings
        all_findings = []
        for finding in scan_data.get('sast_findings', []):
            all_findings.append({**finding, 'type': 'SAST'})
        for finding in scan_data.get('sca_findings', []):
            all_findings.append({**finding, 'type': 'SCA'})
        for finding in scan_data.get('secret_findings', []):
            all_findings.append({**finding, 'type': 'SECRET'})

        # Sort by severity
        severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_findings.sort(key=lambda x: (severity_priority.get(x.get('severity', 'info').lower(), 5),
                                         -float(x.get('cvss_score', 0))))

        for idx, finding in enumerate(all_findings[:10], start=1):
            ws.cell(row, 1, idx)
            ws.cell(row, 2, finding['type'])
            ws.cell(row, 3, finding.get('severity', '').upper())
            ws.cell(row, 4, finding.get('title', finding.get('vulnerability', finding.get('secret_type', 'N/A'))))
            ws.cell(row, 5, finding.get('file_path', finding.get('package', 'N/A')))
            ws.cell(row, 6, finding.get('line_number', finding.get('installed_version', 'N/A')))
            ws.cell(row, 7, finding.get('cwe_id', finding.get('cve', 'N/A')))
            ws.cell(row, 8, finding.get('cvss_score', 'N/A'))

            # Color code severity
            severity = finding.get('severity', '').lower()
            if severity in self.SEVERITY_COLORS:
                severity_cell = ws.cell(row, 3)
                severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                end_color=self.SEVERITY_COLORS[severity],
                                                fill_type="solid")
                if severity in ['critical', 'high']:
                    severity_cell.font = Font(color="FFFFFF", bold=True)

            row += 1

        # Auto-size columns
        for col in range(1, 11):
            ws.column_dimensions[get_column_letter(col)].width = 20

    def _create_sast_detailed_sheet(self, wb: Workbook, findings: List[Dict], severity: str, styles: Dict):
        """Create detailed SAST findings sheet for specific severity"""
        sheet_name = f"SAST - {severity.upper()}"
        ws = wb.create_sheet(sheet_name)

        # Title
        ws['A1'] = f"SAST Findings - {severity.upper()} Severity"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:L1')

        # Count
        ws['A2'] = f"Total Findings: {len(findings)}"
        ws['A2'].font = styles['bold_font']

        # Headers
        row = 4
        headers = ['#', 'Title', 'Severity', 'CWE ID', 'CWE Name', 'OWASP', 'File Path',
                   'Line', 'CVSS', 'Description', 'Remediation', 'Code Snippet']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']
            cell.alignment = styles['center_align']

        row += 1

        # Data rows
        for idx, finding in enumerate(findings, start=1):
            ws.cell(row, 1, idx)
            ws.cell(row, 2, finding.get('title', 'N/A'))
            ws.cell(row, 3, finding.get('severity', '').upper())
            ws.cell(row, 4, finding.get('cwe_id', 'N/A'))
            ws.cell(row, 5, finding.get('cwe_name', 'N/A'))
            ws.cell(row, 6, finding.get('owasp_category', 'N/A'))
            ws.cell(row, 7, finding.get('file_path', 'N/A'))
            ws.cell(row, 8, finding.get('line_number', 'N/A'))
            ws.cell(row, 9, finding.get('cvss_score', 'N/A'))
            ws.cell(row, 10, finding.get('description', 'N/A'))
            ws.cell(row, 11, finding.get('remediation', 'N/A'))
            ws.cell(row, 12, finding.get('code_snippet', finding.get('vulnerable_code', 'N/A')))

            # Color code severity
            severity_cell = ws.cell(row, 3)
            severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity.lower()],
                                            end_color=self.SEVERITY_COLORS[severity.lower()],
                                            fill_type="solid")
            if severity.lower() in ['critical', 'high']:
                severity_cell.font = Font(color="FFFFFF", bold=True)

            # Set row height for readability
            ws.row_dimensions[row].height = 60

            # Apply borders
            for col in range(1, 13):
                ws.cell(row, col).border = styles['border']
                ws.cell(row, col).alignment = styles['left_align']

            row += 1

        # Auto-size columns
        column_widths = [5, 30, 12, 12, 25, 20, 35, 8, 8, 40, 40, 40]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

        # Freeze header row
        ws.freeze_panes = 'A5'

    def _create_sast_by_cwe_sheet(self, wb: Workbook, findings: List[Dict], styles: Dict):
        """Create SAST findings grouped by CWE"""
        ws = wb.create_sheet("SAST - By CWE")

        # Title
        ws['A1'] = "SAST Findings Grouped by CWE"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:H1')

        # Group by CWE
        cwe_groups = defaultdict(list)
        for finding in findings:
            cwe = finding.get('cwe_id', 'Unknown')
            cwe_groups[cwe].append(finding)

        # Sort by count
        sorted_cwes = sorted(cwe_groups.items(), key=lambda x: len(x[1]), reverse=True)

        row = 3
        for cwe_id, cwe_findings in sorted_cwes:
            # CWE Header
            cwe_name = cwe_findings[0].get('cwe_name', 'Unknown CWE')
            ws[f'A{row}'] = f"{cwe_id}: {cwe_name}"
            ws[f'A{row}'].font = styles['subtitle_font']
            ws.merge_cells(f'A{row}:H{row}')
            row += 1

            ws[f'A{row}'] = f"Total Findings: {len(cwe_findings)}"
            ws[f'A{row}'].font = styles['bold_font']
            row += 1

            # Headers
            headers = ['#', 'Severity', 'Title', 'File Path', 'Line', 'CVSS', 'OWASP', 'Remediation']
            for col, header in enumerate(headers, start=1):
                cell = ws.cell(row, col, header)
                cell.fill = styles['header_fill']
                cell.font = styles['header_font']

            row += 1

            # Findings
            for idx, finding in enumerate(cwe_findings, start=1):
                ws.cell(row, 1, idx)
                ws.cell(row, 2, finding.get('severity', '').upper())
                ws.cell(row, 3, finding.get('title', 'N/A'))
                ws.cell(row, 4, finding.get('file_path', 'N/A'))
                ws.cell(row, 5, finding.get('line_number', 'N/A'))
                ws.cell(row, 6, finding.get('cvss_score', 'N/A'))
                ws.cell(row, 7, finding.get('owasp_category', 'N/A'))
                ws.cell(row, 8, finding.get('remediation', 'N/A'))

                # Color code severity
                severity = finding.get('severity', '').lower()
                if severity in self.SEVERITY_COLORS:
                    severity_cell = ws.cell(row, 2)
                    severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                    end_color=self.SEVERITY_COLORS[severity],
                                                    fill_type="solid")
                    if severity in ['critical', 'high']:
                        severity_cell.font = Font(color="FFFFFF", bold=True)

                row += 1

            row += 2  # Space between groups

        # Auto-size columns
        column_widths = [5, 12, 35, 40, 8, 8, 20, 40]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_sast_by_owasp_sheet(self, wb: Workbook, findings: List[Dict], styles: Dict):
        """Create SAST findings grouped by OWASP category"""
        ws = wb.create_sheet("SAST - By OWASP")

        # Title
        ws['A1'] = "SAST Findings Grouped by OWASP Top 10"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:H1')

        # Group by OWASP
        owasp_groups = defaultdict(list)
        for finding in findings:
            owasp = finding.get('owasp_category', 'Uncategorized')
            owasp_groups[owasp].append(finding)

        # Sort by OWASP category
        sorted_owasp = sorted(owasp_groups.items(), key=lambda x: x[0])

        row = 3
        for owasp_cat, owasp_findings in sorted_owasp:
            # OWASP Header
            ws[f'A{row}'] = owasp_cat
            ws[f'A{row}'].font = styles['subtitle_font']
            ws.merge_cells(f'A{row}:H{row}')
            row += 1

            ws[f'A{row}'] = f"Total Findings: {len(owasp_findings)}"
            ws[f'A{row}'].font = styles['bold_font']
            row += 1

            # Headers
            headers = ['#', 'Severity', 'Title', 'CWE', 'File Path', 'Line', 'CVSS', 'Remediation']
            for col, header in enumerate(headers, start=1):
                cell = ws.cell(row, col, header)
                cell.fill = styles['header_fill']
                cell.font = styles['header_font']

            row += 1

            # Findings
            for idx, finding in enumerate(owasp_findings, start=1):
                ws.cell(row, 1, idx)
                ws.cell(row, 2, finding.get('severity', '').upper())
                ws.cell(row, 3, finding.get('title', 'N/A'))
                ws.cell(row, 4, finding.get('cwe_id', 'N/A'))
                ws.cell(row, 5, finding.get('file_path', 'N/A'))
                ws.cell(row, 6, finding.get('line_number', 'N/A'))
                ws.cell(row, 7, finding.get('cvss_score', 'N/A'))
                ws.cell(row, 8, finding.get('remediation', 'N/A'))

                # Color code severity
                severity = finding.get('severity', '').lower()
                if severity in self.SEVERITY_COLORS:
                    severity_cell = ws.cell(row, 2)
                    severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                    end_color=self.SEVERITY_COLORS[severity],
                                                    fill_type="solid")
                    if severity in ['critical', 'high']:
                        severity_cell.font = Font(color="FFFFFF", bold=True)

                row += 1

            row += 2

        # Auto-size columns
        column_widths = [5, 12, 35, 15, 40, 8, 8, 40]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_sast_by_file_sheet(self, wb: Workbook, findings: List[Dict], styles: Dict):
        """Create SAST findings grouped by file"""
        ws = wb.create_sheet("SAST - By File")

        # Title
        ws['A1'] = "SAST Findings Grouped by File"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:H1')

        # Group by file
        file_groups = defaultdict(list)
        for finding in findings:
            file_path = finding.get('file_path', 'Unknown')
            file_groups[file_path].append(finding)

        # Sort by count
        sorted_files = sorted(file_groups.items(), key=lambda x: len(x[1]), reverse=True)

        row = 3
        for file_path, file_findings in sorted_files:
            # File Header
            ws[f'A{row}'] = file_path
            ws[f'A{row}'].font = styles['subtitle_font']
            ws.merge_cells(f'A{row}:H{row}')
            row += 1

            ws[f'A{row}'] = f"Total Findings: {len(file_findings)}"
            ws[f'A{row}'].font = styles['bold_font']
            row += 1

            # Headers
            headers = ['#', 'Severity', 'Title', 'CWE', 'Line', 'CVSS', 'OWASP', 'Remediation']
            for col, header in enumerate(headers, start=1):
                cell = ws.cell(row, col, header)
                cell.fill = styles['header_fill']
                cell.font = styles['header_font']

            row += 1

            # Sort findings by line number
            file_findings.sort(key=lambda x: x.get('line_number', 0))

            # Findings
            for idx, finding in enumerate(file_findings, start=1):
                ws.cell(row, 1, idx)
                ws.cell(row, 2, finding.get('severity', '').upper())
                ws.cell(row, 3, finding.get('title', 'N/A'))
                ws.cell(row, 4, finding.get('cwe_id', 'N/A'))
                ws.cell(row, 5, finding.get('line_number', 'N/A'))
                ws.cell(row, 6, finding.get('cvss_score', 'N/A'))
                ws.cell(row, 7, finding.get('owasp_category', 'N/A'))
                ws.cell(row, 8, finding.get('remediation', 'N/A'))

                # Color code severity
                severity = finding.get('severity', '').lower()
                if severity in self.SEVERITY_COLORS:
                    severity_cell = ws.cell(row, 2)
                    severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                    end_color=self.SEVERITY_COLORS[severity],
                                                    fill_type="solid")
                    if severity in ['critical', 'high']:
                        severity_cell.font = Font(color="FFFFFF", bold=True)

                row += 1

            row += 2

        # Auto-size columns
        column_widths = [5, 12, 35, 15, 8, 8, 20, 40]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_sca_detailed_sheet(self, wb: Workbook, findings: List[Dict], severity: str, styles: Dict):
        """Create detailed SCA findings sheet for specific severity"""
        sheet_name = f"SCA - {severity.upper()}"
        ws = wb.create_sheet(sheet_name)

        # Title
        ws['A1'] = f"SCA (Dependency) Findings - {severity.upper()} Severity"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:K1')

        # Count
        ws['A2'] = f"Total Findings: {len(findings)}"
        ws['A2'].font = styles['bold_font']

        # Headers
        row = 4
        headers = ['#', 'Package Name', 'Installed Version', 'Fixed Version', 'Vulnerability',
                   'CVE', 'Severity', 'CVSS', 'Description', 'Remediation', 'References']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']
            cell.alignment = styles['center_align']

        row += 1

        # Data rows
        for idx, finding in enumerate(findings, start=1):
            ws.cell(row, 1, idx)
            ws.cell(row, 2, finding.get('package', 'N/A'))
            ws.cell(row, 3, finding.get('installed_version', 'N/A'))
            ws.cell(row, 4, finding.get('fixed_version', finding.get('safe_version', 'N/A')))
            ws.cell(row, 5, finding.get('vulnerability', 'N/A'))
            ws.cell(row, 6, finding.get('cve', 'N/A'))
            ws.cell(row, 7, finding.get('severity', '').upper())
            ws.cell(row, 8, finding.get('cvss_score', 'N/A'))
            ws.cell(row, 9, finding.get('description', 'N/A'))
            ws.cell(row, 10, finding.get('remediation', 'N/A'))
            ws.cell(row, 11, finding.get('references', 'N/A'))

            # Color code severity
            severity_cell = ws.cell(row, 7)
            severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity.lower()],
                                            end_color=self.SEVERITY_COLORS[severity.lower()],
                                            fill_type="solid")
            if severity.lower() in ['critical', 'high']:
                severity_cell.font = Font(color="FFFFFF", bold=True)

            # Set row height
            ws.row_dimensions[row].height = 60

            # Apply borders and alignment
            for col in range(1, 12):
                ws.cell(row, col).border = styles['border']
                ws.cell(row, col).alignment = styles['left_align']

            row += 1

        # Auto-size columns
        column_widths = [5, 25, 15, 15, 30, 18, 12, 8, 40, 40, 30]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

        # Freeze header row
        ws.freeze_panes = 'A5'

    def _create_sca_by_package_sheet(self, wb: Workbook, findings: List[Dict], styles: Dict):
        """Create SCA findings grouped by package"""
        ws = wb.create_sheet("SCA - By Package")

        # Title
        ws['A1'] = "SCA Findings Grouped by Package"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:H1')

        # Group by package
        package_groups = defaultdict(list)
        for finding in findings:
            package = finding.get('package', 'Unknown')
            package_groups[package].append(finding)

        # Sort by package name
        sorted_packages = sorted(package_groups.items())

        row = 3
        for package_name, package_findings in sorted_packages:
            # Package Header
            ws[f'A{row}'] = package_name
            ws[f'A{row}'].font = styles['subtitle_font']
            ws.merge_cells(f'A{row}:H{row}')
            row += 1

            ws[f'A{row}'] = f"Total Vulnerabilities: {len(package_findings)} | Installed Version: {package_findings[0].get('installed_version', 'N/A')}"
            ws[f'A{row}'].font = styles['bold_font']
            row += 1

            # Headers
            headers = ['#', 'Severity', 'CVE', 'Vulnerability', 'CVSS', 'Fixed Version', 'Description', 'Remediation']
            for col, header in enumerate(headers, start=1):
                cell = ws.cell(row, col, header)
                cell.fill = styles['header_fill']
                cell.font = styles['header_font']

            row += 1

            # Findings
            for idx, finding in enumerate(package_findings, start=1):
                ws.cell(row, 1, idx)
                ws.cell(row, 2, finding.get('severity', '').upper())
                ws.cell(row, 3, finding.get('cve', 'N/A'))
                ws.cell(row, 4, finding.get('vulnerability', 'N/A'))
                ws.cell(row, 5, finding.get('cvss_score', 'N/A'))
                ws.cell(row, 6, finding.get('fixed_version', finding.get('safe_version', 'N/A')))
                ws.cell(row, 7, finding.get('description', 'N/A'))
                ws.cell(row, 8, finding.get('remediation', 'N/A'))

                # Color code severity
                severity = finding.get('severity', '').lower()
                if severity in self.SEVERITY_COLORS:
                    severity_cell = ws.cell(row, 2)
                    severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                    end_color=self.SEVERITY_COLORS[severity],
                                                    fill_type="solid")
                    if severity in ['critical', 'high']:
                        severity_cell.font = Font(color="FFFFFF", bold=True)

                row += 1

            row += 2

        # Auto-size columns
        column_widths = [5, 12, 18, 30, 8, 15, 40, 40]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_sca_cve_details_sheet(self, wb: Workbook, findings: List[Dict], styles: Dict):
        """Create detailed CVE information sheet"""
        ws = wb.create_sheet("SCA - CVE Details")

        # Title
        ws['A1'] = "Detailed CVE Information"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:J1')

        # Headers
        row = 3
        headers = ['CVE ID', 'Severity', 'CVSS Score', 'Package', 'Version', 'Description',
                   'References', 'Published Date', 'Remediation', 'Status']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        # Get unique CVEs
        cve_dict = {}
        for finding in findings:
            cve = finding.get('cve', '')
            if cve and cve not in cve_dict:
                cve_dict[cve] = finding

        # Sort by CVSS score
        sorted_cves = sorted(cve_dict.values(),
                           key=lambda x: float(x.get('cvss_score', 0)),
                           reverse=True)

        for finding in sorted_cves:
            ws.cell(row, 1, finding.get('cve', 'N/A'))
            ws.cell(row, 2, finding.get('severity', '').upper())
            ws.cell(row, 3, finding.get('cvss_score', 'N/A'))
            ws.cell(row, 4, finding.get('package', 'N/A'))
            ws.cell(row, 5, finding.get('installed_version', 'N/A'))
            ws.cell(row, 6, finding.get('description', 'N/A'))
            ws.cell(row, 7, finding.get('references', 'N/A'))
            ws.cell(row, 8, finding.get('published_date', 'N/A'))
            ws.cell(row, 9, finding.get('remediation', 'N/A'))
            ws.cell(row, 10, 'Open' if finding.get('severity', '').lower() in ['critical', 'high'] else 'Review')

            # Color code severity
            severity = finding.get('severity', '').lower()
            if severity in self.SEVERITY_COLORS:
                severity_cell = ws.cell(row, 2)
                severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                end_color=self.SEVERITY_COLORS[severity],
                                                fill_type="solid")
                if severity in ['critical', 'high']:
                    severity_cell.font = Font(color="FFFFFF", bold=True)

            ws.row_dimensions[row].height = 50

            for col in range(1, 11):
                ws.cell(row, col).border = styles['border']
                ws.cell(row, col).alignment = styles['left_align']

            row += 1

        # Auto-size columns
        column_widths = [18, 12, 10, 25, 15, 40, 30, 15, 40, 12]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_secrets_detailed_sheet(self, wb: Workbook, findings: List[Dict], styles: Dict):
        """Create detailed secrets detection sheet"""
        ws = wb.create_sheet("Secrets Detection")

        # Title
        ws['A1'] = "Secrets Detection - All Findings"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:I1')

        # Count
        ws['A2'] = f"Total Secrets Found: {len(findings)}"
        ws['A2'].font = Font(bold=True, size=12, color="C00000")

        # Headers
        row = 4
        headers = ['#', 'Secret Type', 'Severity', 'File Path', 'Line', 'Masked Value',
                   'Description', 'Remediation', 'Risk Level']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        # Sort by severity
        severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: severity_priority.get(x.get('severity', 'info').lower(), 5))

        # Data rows
        for idx, finding in enumerate(findings, start=1):
            ws.cell(row, 1, idx)
            ws.cell(row, 2, finding.get('secret_type', 'Unknown'))
            ws.cell(row, 3, finding.get('severity', '').upper())
            ws.cell(row, 4, finding.get('file_path', 'N/A'))
            ws.cell(row, 5, finding.get('line_number', 'N/A'))
            ws.cell(row, 6, finding.get('masked_value', finding.get('match', 'N/A')))
            ws.cell(row, 7, finding.get('description', 'Hardcoded secret detected'))
            ws.cell(row, 8, finding.get('remediation', 'Remove hardcoded secret and use environment variables'))
            ws.cell(row, 9, 'CRITICAL' if finding.get('severity', '').lower() in ['critical', 'high'] else 'MODERATE')

            # Color code severity
            severity = finding.get('severity', '').lower()
            if severity in self.SEVERITY_COLORS:
                severity_cell = ws.cell(row, 3)
                severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                end_color=self.SEVERITY_COLORS[severity],
                                                fill_type="solid")
                if severity in ['critical', 'high']:
                    severity_cell.font = Font(color="FFFFFF", bold=True)

            ws.row_dimensions[row].height = 50

            for col in range(1, 10):
                ws.cell(row, col).border = styles['border']
                ws.cell(row, col).alignment = styles['left_align']

            row += 1

        # Auto-size columns
        column_widths = [5, 25, 12, 40, 8, 30, 35, 40, 15]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_threat_model_sheet(self, wb: Workbook, threat_model: Dict[str, Any], styles: Dict):
        """Create detailed threat model (STRIDE) sheet"""
        ws = wb.create_sheet("Threat Model - STRIDE")

        # Title
        ws['A1'] = "Threat Model - STRIDE Analysis"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:H1')

        # Description
        row = 3
        ws[f'A{row}'] = "STRIDE Threat Modeling Framework"
        ws[f'A{row}'].font = styles['subtitle_font']
        ws.merge_cells(f'A{row}:H{row}')
        row += 1

        ws[f'A{row}'] = "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege"
        ws.merge_cells(f'A{row}:H{row}')
        row += 2

        # STRIDE Categories
        stride_analysis = threat_model.get('stride_analysis', {})
        stride_categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure',
                            'Denial of Service', 'Elevation of Privilege']

        for category in stride_categories:
            threats = stride_analysis.get(category, stride_analysis.get(category.lower(), []))

            if threats:
                # Category Header
                ws[f'A{row}'] = f"{category} Threats ({len(threats)} identified)"
                ws[f'A{row}'].font = styles['subtitle_font']
                ws[f'A{row}'].fill = PatternFill(start_color="E7E6E6", end_color="E7E6E6", fill_type="solid")
                ws.merge_cells(f'A{row}:H{row}')
                row += 1

                # Headers
                headers = ['#', 'Component', 'Threat', 'Description', 'Impact', 'Likelihood',
                          'Mitigation', 'Status']
                for col, header in enumerate(headers, start=1):
                    cell = ws.cell(row, col, header)
                    cell.fill = styles['header_fill']
                    cell.font = styles['header_font']

                row += 1

                # Threats
                for idx, threat in enumerate(threats, start=1):
                    ws.cell(row, 1, idx)
                    ws.cell(row, 2, threat.get('component', threat.get('asset', 'N/A')))
                    ws.cell(row, 3, threat.get('threat', threat.get('title', 'N/A')))
                    ws.cell(row, 4, threat.get('description', 'N/A'))
                    ws.cell(row, 5, threat.get('impact', 'High'))
                    ws.cell(row, 6, threat.get('likelihood', 'Medium'))
                    ws.cell(row, 7, threat.get('mitigation', threat.get('recommendation', 'N/A')))
                    ws.cell(row, 8, threat.get('status', 'Open'))

                    ws.row_dimensions[row].height = 50

                    for col in range(1, 9):
                        ws.cell(row, col).border = styles['border']
                        ws.cell(row, col).alignment = styles['left_align']

                    row += 1

                row += 2  # Space between categories

        # Trust Boundaries
        trust_boundaries = threat_model.get('trust_boundaries', [])
        if trust_boundaries:
            ws[f'A{row}'] = "Trust Boundaries Identified"
            ws[f'A{row}'].font = styles['subtitle_font']
            ws.merge_cells(f'A{row}:H{row}')
            row += 1

            for idx, boundary in enumerate(trust_boundaries, start=1):
                ws[f'A{row}'] = f"{idx}. {boundary}"
                ws.merge_cells(f'A{row}:H{row}')
                row += 1

        # Auto-size columns
        column_widths = [5, 20, 30, 35, 12, 12, 40, 12]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_mitre_attack_sheet(self, wb: Workbook, threat_model: Dict[str, Any], styles: Dict):
        """Create MITRE ATT&CK mapping sheet"""
        ws = wb.create_sheet("MITRE ATT&CK Mapping")

        # Title
        ws['A1'] = "MITRE ATT&CK Technique Mapping"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:G1')

        # Description
        row = 3
        ws[f'A{row}'] = "Mapping of identified threats to MITRE ATT&CK framework"
        ws.merge_cells(f'A{row}:G{row}')
        row += 2

        # Headers
        headers = ['Technique ID', 'Technique Name', 'Tactic', 'Description',
                  'Related Threat', 'Mitigation', 'Detection']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        # Get MITRE mappings
        mitre_techniques = threat_model.get('mitre_attack_techniques', [])

        # If no direct MITRE mappings, extract from STRIDE analysis
        if not mitre_techniques:
            stride_analysis = threat_model.get('stride_analysis', {})
            for category, threats in stride_analysis.items():
                for threat in threats:
                    if 'mitre' in threat or 'technique' in threat:
                        mitre_techniques.append(threat)

        # Common MITRE ATT&CK techniques for application security
        default_techniques = [
            {
                'id': 'T1190',
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Adversaries may attempt to exploit weaknesses in Internet-facing applications',
                'mitigation': 'Application isolation, security scanning, input validation',
                'detection': 'Application logs, WAF alerts'
            },
            {
                'id': 'T1059',
                'name': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse command interpreters to execute commands',
                'mitigation': 'Input validation, least privilege, code review',
                'detection': 'Process monitoring, command-line analysis'
            },
            {
                'id': 'T1078',
                'name': 'Valid Accounts',
                'tactic': 'Persistence',
                'description': 'Adversaries may obtain credentials to gain access',
                'mitigation': 'Multi-factor authentication, credential rotation',
                'detection': 'Authentication logs, anomalous login detection'
            },
            {
                'id': 'T1548',
                'name': 'Abuse Elevation Control Mechanism',
                'tactic': 'Privilege Escalation',
                'description': 'Adversaries may circumvent access controls',
                'mitigation': 'Principle of least privilege, input validation',
                'detection': 'Process monitoring, API monitoring'
            },
            {
                'id': 'T1070',
                'name': 'Indicator Removal',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may delete or modify artifacts',
                'mitigation': 'Centralized logging, file integrity monitoring',
                'detection': 'Log analysis, file monitoring'
            },
            {
                'id': 'T1552',
                'name': 'Unsecured Credentials',
                'tactic': 'Credential Access',
                'description': 'Adversaries may search for credentials in insecure locations',
                'mitigation': 'Secrets management, encryption, code review',
                'detection': 'File monitoring, secret scanning'
            },
            {
                'id': 'T1087',
                'name': 'Account Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to enumerate accounts',
                'mitigation': 'Rate limiting, authentication monitoring',
                'detection': 'API monitoring, authentication logs'
            },
            {
                'id': 'T1530',
                'name': 'Data from Cloud Storage',
                'tactic': 'Collection',
                'description': 'Adversaries may access data from cloud storage',
                'mitigation': 'Access controls, encryption, monitoring',
                'detection': 'Cloud audit logs, access monitoring'
            },
            {
                'id': 'T1041',
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may steal data over their command and control channel',
                'mitigation': 'Network segmentation, DLP, egress filtering',
                'detection': 'Network monitoring, anomaly detection'
            },
            {
                'id': 'T1499',
                'name': 'Endpoint Denial of Service',
                'tactic': 'Impact',
                'description': 'Adversaries may perform DoS attacks',
                'mitigation': 'Rate limiting, resource quotas, WAF',
                'detection': 'Performance monitoring, traffic analysis'
            },
        ]

        # Use provided techniques or defaults
        techniques_to_display = mitre_techniques if mitre_techniques else default_techniques

        for technique in techniques_to_display:
            ws.cell(row, 1, technique.get('id', technique.get('technique_id', 'N/A')))
            ws.cell(row, 2, technique.get('name', technique.get('technique_name', 'N/A')))
            ws.cell(row, 3, technique.get('tactic', 'N/A'))
            ws.cell(row, 4, technique.get('description', 'N/A'))
            ws.cell(row, 5, technique.get('related_threat', technique.get('threat', 'See threat model')))
            ws.cell(row, 6, technique.get('mitigation', 'N/A'))
            ws.cell(row, 7, technique.get('detection', 'N/A'))

            ws.row_dimensions[row].height = 50

            for col in range(1, 8):
                ws.cell(row, col).border = styles['border']
                ws.cell(row, col).alignment = styles['left_align']

            row += 1

        # Auto-size columns
        column_widths = [12, 30, 18, 40, 30, 40, 40]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _create_remediation_summary_sheet(self, wb: Workbook, scan_data: Dict[str, Any], styles: Dict):
        """Create consolidated remediation summary"""
        ws = wb.create_sheet("Remediation Summary")

        # Title
        ws['A1'] = "Remediation Action Plan"
        ws['A1'].font = styles['title_font']
        ws.merge_cells('A1:G1')

        row = 3
        ws[f'A{row}'] = "Prioritized Remediation Recommendations"
        ws[f'A{row}'].font = styles['subtitle_font']
        ws.merge_cells(f'A{row}:G{row}')
        row += 1

        # Headers
        headers = ['Priority', 'Type', 'Issue', 'Location', 'Severity', 'Effort', 'Remediation Action']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = styles['header_fill']
            cell.font = styles['header_font']

        row += 1

        # Collect all remediations
        remediations = []

        # SAST
        for finding in scan_data.get('sast_findings', []):
            remediations.append({
                'type': 'SAST',
                'issue': finding.get('title', 'N/A'),
                'location': f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}",
                'severity': finding.get('severity', 'info'),
                'remediation': finding.get('remediation', 'N/A'),
                'cvss': float(finding.get('cvss_score', 0))
            })

        # SCA
        for finding in scan_data.get('sca_findings', []):
            remediations.append({
                'type': 'SCA',
                'issue': f"{finding.get('package', 'N/A')} - {finding.get('vulnerability', 'N/A')}",
                'location': f"{finding.get('package', 'N/A')} v{finding.get('installed_version', 'N/A')}",
                'severity': finding.get('severity', 'info'),
                'remediation': finding.get('remediation', f"Update to version {finding.get('fixed_version', 'latest')}"),
                'cvss': float(finding.get('cvss_score', 0))
            })

        # Secrets
        for finding in scan_data.get('secret_findings', []):
            remediations.append({
                'type': 'SECRET',
                'issue': finding.get('secret_type', 'Hardcoded Secret'),
                'location': f"{finding.get('file_path', 'N/A')}:{finding.get('line_number', 'N/A')}",
                'severity': finding.get('severity', 'high'),
                'remediation': finding.get('remediation', 'Remove hardcoded secret, use environment variables'),
                'cvss': 9.0 if finding.get('severity', '').lower() == 'critical' else 7.0
            })

        # Sort by severity and CVSS
        severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        remediations.sort(key=lambda x: (severity_priority.get(x['severity'].lower(), 5), -x['cvss']))

        # Add to sheet
        for idx, rem in enumerate(remediations[:50], start=1):  # Top 50
            ws.cell(row, 1, idx)
            ws.cell(row, 2, rem['type'])
            ws.cell(row, 3, rem['issue'])
            ws.cell(row, 4, rem['location'])
            ws.cell(row, 5, rem['severity'].upper())

            # Estimate effort
            effort = 'Low' if rem['type'] == 'SCA' else ('High' if rem['severity'].lower() == 'critical' else 'Medium')
            ws.cell(row, 6, effort)
            ws.cell(row, 7, rem['remediation'])

            # Color code severity
            severity = rem['severity'].lower()
            if severity in self.SEVERITY_COLORS:
                severity_cell = ws.cell(row, 5)
                severity_cell.fill = PatternFill(start_color=self.SEVERITY_COLORS[severity],
                                                end_color=self.SEVERITY_COLORS[severity],
                                                fill_type="solid")
                if severity in ['critical', 'high']:
                    severity_cell.font = Font(color="FFFFFF", bold=True)

            ws.row_dimensions[row].height = 50

            for col in range(1, 8):
                ws.cell(row, col).border = styles['border']
                ws.cell(row, col).alignment = styles['left_align']

            row += 1

        # Auto-size columns
        column_widths = [8, 10, 35, 35, 12, 10, 50]
        for idx, width in enumerate(column_widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = width

    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_all_severities(self, scan_data: Dict[str, Any]) -> Dict[str, int]:
        """Count all findings across all scan types by severity"""
        all_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for scan_type in ['sast_findings', 'sca_findings', 'secret_findings']:
            findings = scan_data.get(scan_type, [])
            counts = self._count_by_severity(findings)
            for severity, count in counts.items():
                all_counts[severity] += count

        return all_counts

    def _get_total_findings(self, scan_data: Dict[str, Any]) -> int:
        """Get total number of findings across all scan types"""
        total = 0
        total += len(scan_data.get('sast_findings', []))
        total += len(scan_data.get('sca_findings', []))
        total += len(scan_data.get('secret_findings', []))
        return total

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate risk score based on severity distribution"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        score = sum(severity_counts.get(sev, 0) * weight for sev, weight in weights.items())
        return score

    def generate_pdf_report(self, scan_data: Dict[str, Any], output_path: str = None) -> BytesIO:
        """Generate comprehensive PDF report with detailed findings"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                              topMargin=0.5*inch, bottomMargin=0.5*inch,
                              leftMargin=0.75*inch, rightMargin=0.75*inch)

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                     fontSize=24, textColor=colors.HexColor('#366092'),
                                     spaceAfter=30)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading1'],
                                      fontSize=16, textColor=colors.HexColor('#366092'),
                                      spaceAfter=12)
        subheading_style = ParagraphStyle('CustomSubHeading', parent=styles['Heading2'],
                                         fontSize=12, textColor=colors.HexColor('#366092'),
                                         spaceAfter=8)
        normal_style = styles['Normal']

        # Build content
        story = []

        # Cover Page
        story.append(Paragraph("Application Security", title_style))
        story.append(Paragraph("Detailed Scan Report", title_style))
        story.append(Spacer(1, 0.5*inch))

        # Metadata
        metadata = [
            ['Project:', scan_data.get('project_name', 'Unknown')],
            ['Report Date:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ['Scan Types:', ', '.join(scan_data.get('scan_types', []))],
            ['Total Findings:', str(self._get_total_findings(scan_data))],
        ]
        metadata_table = Table(metadata, colWidths=[2*inch, 4.5*inch])
        metadata_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 0.5*inch))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))

        severity_counts = self._count_all_severities(scan_data)
        risk_score = self._calculate_risk_score(severity_counts)

        summary_text = f"""
        This report presents a comprehensive security analysis of {scan_data.get('project_name', 'the application')}.
        The scan identified <b>{self._get_total_findings(scan_data)} total findings</b> across multiple security domains
        with an overall risk score of <b>{risk_score:.1f}</b>.
        """
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 0.2*inch))

        # Severity Distribution Table
        summary_data = [['Severity', 'Count', 'Percentage']]
        total_findings = self._get_total_findings(scan_data)

        for severity in self.SEVERITY_ORDER:
            count = severity_counts.get(severity, 0)
            if count > 0:
                percentage = (count / total_findings * 100) if total_findings > 0 else 0
                summary_data.append([severity.upper(), str(count), f"{percentage:.1f}%"])

        summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#366092')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        story.append(summary_table)
        story.append(PageBreak())

        # Detailed Findings by Category
        story.append(Paragraph("Detailed Findings", heading_style))

        # SAST Findings
        sast_findings = scan_data.get('sast_findings', [])
        if sast_findings:
            story.append(Paragraph(f"SAST (Static Analysis) - {len(sast_findings)} Findings", subheading_style))

            sast_severity = self._count_by_severity(sast_findings)
            sast_summary = f"Critical: {sast_severity['critical']}, High: {sast_severity['high']}, " \
                          f"Medium: {sast_severity['medium']}, Low: {sast_severity['low']}"
            story.append(Paragraph(sast_summary, normal_style))
            story.append(Spacer(1, 0.1*inch))

            # Top SAST findings
            critical_high = [f for f in sast_findings if f.get('severity', '').lower() in ['critical', 'high']][:10]
            if critical_high:
                sast_data = [['#', 'Severity', 'Title', 'File', 'Line']]
                for idx, finding in enumerate(critical_high, 1):
                    sast_data.append([
                        str(idx),
                        finding.get('severity', '').upper(),
                        finding.get('title', 'N/A')[:40],
                        finding.get('file_path', 'N/A')[:30],
                        str(finding.get('line_number', 'N/A'))
                    ])

                sast_table = Table(sast_data, colWidths=[0.3*inch, 0.8*inch, 2.2*inch, 2*inch, 0.5*inch])
                sast_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#366092')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(sast_table)
            story.append(Spacer(1, 0.3*inch))

        # SCA Findings
        sca_findings = scan_data.get('sca_findings', [])
        if sca_findings:
            story.append(Paragraph(f"SCA (Dependency Analysis) - {len(sca_findings)} Findings", subheading_style))

            sca_severity = self._count_by_severity(sca_findings)
            sca_summary = f"Critical: {sca_severity['critical']}, High: {sca_severity['high']}, " \
                         f"Medium: {sca_severity['medium']}, Low: {sca_severity['low']}"
            story.append(Paragraph(sca_summary, normal_style))
            story.append(Spacer(1, 0.1*inch))

            # Top SCA findings
            critical_high_sca = [f for f in sca_findings if f.get('severity', '').lower() in ['critical', 'high']][:10]
            if critical_high_sca:
                sca_data = [['#', 'Severity', 'Package', 'CVE', 'CVSS']]
                for idx, finding in enumerate(critical_high_sca, 1):
                    sca_data.append([
                        str(idx),
                        finding.get('severity', '').upper(),
                        finding.get('package', 'N/A')[:35],
                        finding.get('cve', 'N/A'),
                        str(finding.get('cvss_score', 'N/A'))
                    ])

                sca_table = Table(sca_data, colWidths=[0.3*inch, 0.8*inch, 2.5*inch, 1.5*inch, 0.7*inch])
                sca_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#366092')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                story.append(sca_table)
            story.append(Spacer(1, 0.3*inch))

        # Secrets
        secret_findings = scan_data.get('secret_findings', [])
        if secret_findings:
            story.append(Paragraph(f"Secrets Detection - {len(secret_findings)} Findings", subheading_style))
            story.append(Paragraph("Hardcoded secrets detected in source code. Immediate action required.", normal_style))
            story.append(Spacer(1, 0.3*inch))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Remediation Recommendations", heading_style))

        recommendations_text = """
        <b>Immediate Actions Required:</b><br/>
        1. Address all Critical and High severity findings<br/>
        2. Remove hardcoded secrets and implement secure credential management<br/>
        3. Update vulnerable dependencies to patched versions<br/>
        4. Implement secure coding practices for identified CWE categories<br/>
        5. Schedule regular security scans as part of CI/CD pipeline<br/><br/>

        <b>Risk Mitigation Strategy:</b><br/>
        Prioritize remediation based on CVSS scores and exploitability. Focus on issues with public exploits first.
        """
        story.append(Paragraph(recommendations_text, normal_style))

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        if output_path:
            with open(output_path, 'wb') as f:
                f.write(buffer.getvalue())
            return output_path

        return buffer

    def generate_xml_report(self, scan_data: Dict[str, Any], output_path: str = None) -> str:
        """Generate detailed XML report for tool integration"""
        root = ET.Element('SecurityScanReport', version='2.0')

        # Metadata
        metadata = ET.SubElement(root, 'Metadata')
        ET.SubElement(metadata, 'ReportDate').text = datetime.now().isoformat()
        ET.SubElement(metadata, 'ProjectName').text = scan_data.get('project_name', 'Unknown')
        ET.SubElement(metadata, 'ScanTypes').text = ','.join(scan_data.get('scan_types', []))
        ET.SubElement(metadata, 'TotalFindings').text = str(self._get_total_findings(scan_data))

        # Risk Score
        severity_counts = self._count_all_severities(scan_data)
        risk_score = self._calculate_risk_score(severity_counts)
        ET.SubElement(metadata, 'RiskScore').text = str(risk_score)

        # Severity Summary
        severity_summary = ET.SubElement(root, 'SeveritySummary')
        for severity in self.SEVERITY_ORDER:
            count = severity_counts.get(severity, 0)
            ET.SubElement(severity_summary, severity.capitalize(), count=str(count))

        # SAST Findings
        sast_findings = scan_data.get('sast_findings', [])
        if sast_findings:
            sast = ET.SubElement(root, 'SASTFindings', count=str(len(sast_findings)))
            for finding in sast_findings:
                vuln = ET.SubElement(sast, 'Vulnerability',
                                    severity=finding.get('severity', ''),
                                    cvss=str(finding.get('cvss_score', '')))
                ET.SubElement(vuln, 'Title').text = finding.get('title', '')
                ET.SubElement(vuln, 'CWE').text = finding.get('cwe_id', '')
                ET.SubElement(vuln, 'CWEName').text = finding.get('cwe_name', '')
                ET.SubElement(vuln, 'OWASP').text = finding.get('owasp_category', '')
                ET.SubElement(vuln, 'FilePath').text = finding.get('file_path', '')
                ET.SubElement(vuln, 'LineNumber').text = str(finding.get('line_number', ''))
                ET.SubElement(vuln, 'Description').text = finding.get('description', '')
                ET.SubElement(vuln, 'Remediation').text = finding.get('remediation', '')
                ET.SubElement(vuln, 'CodeSnippet').text = finding.get('code_snippet', finding.get('vulnerable_code', ''))

        # SCA Findings
        sca_findings = scan_data.get('sca_findings', [])
        if sca_findings:
            sca = ET.SubElement(root, 'SCAFindings', count=str(len(sca_findings)))
            for finding in sca_findings:
                dep = ET.SubElement(sca, 'Dependency',
                                   severity=finding.get('severity', ''),
                                   cvss=str(finding.get('cvss_score', '')))
                ET.SubElement(dep, 'Package').text = finding.get('package', '')
                ET.SubElement(dep, 'InstalledVersion').text = finding.get('installed_version', '')
                ET.SubElement(dep, 'FixedVersion').text = finding.get('fixed_version', finding.get('safe_version', ''))
                ET.SubElement(dep, 'Vulnerability').text = finding.get('vulnerability', '')
                ET.SubElement(dep, 'CVE').text = finding.get('cve', '')
                ET.SubElement(dep, 'Description').text = finding.get('description', '')
                ET.SubElement(dep, 'Remediation').text = finding.get('remediation', '')
                ET.SubElement(dep, 'References').text = finding.get('references', '')

        # Secret Findings
        secret_findings = scan_data.get('secret_findings', [])
        if secret_findings:
            secrets = ET.SubElement(root, 'SecretFindings', count=str(len(secret_findings)))
            for finding in secret_findings:
                secret = ET.SubElement(secrets, 'Secret', severity=finding.get('severity', ''))
                ET.SubElement(secret, 'Type').text = finding.get('secret_type', '')
                ET.SubElement(secret, 'FilePath').text = finding.get('file_path', '')
                ET.SubElement(secret, 'LineNumber').text = str(finding.get('line_number', ''))
                ET.SubElement(secret, 'MaskedValue').text = finding.get('masked_value', '')
                ET.SubElement(secret, 'Remediation').text = finding.get('remediation', '')

        # Threat Model
        threat_model = scan_data.get('threat_model', {})
        if threat_model:
            tm = ET.SubElement(root, 'ThreatModel')
            stride_analysis = threat_model.get('stride_analysis', {})
            for category, threats in stride_analysis.items():
                cat_elem = ET.SubElement(tm, 'STRIDECategory', name=category)
                for threat in threats:
                    threat_elem = ET.SubElement(cat_elem, 'Threat')
                    ET.SubElement(threat_elem, 'Component').text = threat.get('component', threat.get('asset', ''))
                    ET.SubElement(threat_elem, 'Description').text = threat.get('description', '')
                    ET.SubElement(threat_elem, 'Mitigation').text = threat.get('mitigation', threat.get('recommendation', ''))

        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(xml_str)
            return output_path

        return xml_str
