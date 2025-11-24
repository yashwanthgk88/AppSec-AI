"""
Report Export Service - Generate Excel, PDF, and XML reports
"""
from typing import List, Dict, Any
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from io import BytesIO

class ReportService:
    """Service for generating security reports in multiple formats"""

    def generate_excel_report(self, scan_data: Dict[str, Any], output_path: str = None) -> BytesIO:
        """
        Generate comprehensive Excel report with multiple sheets

        Sheets:
        1. Executive Summary
        2. Vulnerabilities (SAST)
        3. Dependencies (SCA)
        4. Secrets
        5. Threat Model (STRIDE)
        6. MITRE ATT&CK Mapping
        """
        wb = Workbook()
        wb.remove(wb.active)  # Remove default sheet

        # Styles
        header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True, size=12)
        critical_fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
        high_fill = PatternFill(start_color="FF6B6B", end_color="FF6B6B", fill_type="solid")
        medium_fill = PatternFill(start_color="FFA500", end_color="FFA500", fill_type="solid")
        low_fill = PatternFill(start_color="FFEB3B", end_color="FFEB3B", fill_type="solid")

        # Sheet 1: Executive Summary
        ws_summary = wb.create_sheet("Executive Summary")
        self._create_summary_sheet(ws_summary, scan_data, header_fill, header_font)

        # Sheet 2: Vulnerabilities
        if scan_data.get('sast_findings'):
            ws_vulns = wb.create_sheet("Vulnerabilities (SAST)")
            self._create_vulnerabilities_sheet(ws_vulns, scan_data['sast_findings'], header_fill, header_font)

        # Sheet 3: Dependencies
        if scan_data.get('sca_findings'):
            ws_deps = wb.create_sheet("Dependencies (SCA)")
            self._create_dependencies_sheet(ws_deps, scan_data['sca_findings'], header_fill, header_font)

        # Sheet 4: Secrets
        if scan_data.get('secret_findings'):
            ws_secrets = wb.create_sheet("Secrets Detected")
            self._create_secrets_sheet(ws_secrets, scan_data['secret_findings'], header_fill, header_font)

        # Sheet 5: Threat Model
        if scan_data.get('threat_model'):
            ws_threats = wb.create_sheet("Threat Model (STRIDE)")
            self._create_threat_model_sheet(ws_threats, scan_data['threat_model'], header_fill, header_font)

        # Save or return
        if output_path:
            wb.save(output_path)
            return output_path
        else:
            buffer = BytesIO()
            wb.save(buffer)
            buffer.seek(0)
            return buffer

    def _create_summary_sheet(self, ws, scan_data, header_fill, header_font):
        """Create executive summary sheet"""
        # Title
        ws['A1'] = "Application Security Scan Report"
        ws['A1'].font = Font(bold=True, size=16)
        ws.merge_cells('A1:D1')

        # Metadata
        row = 3
        ws[f'A{row}'] = "Report Generated:"
        ws[f'B{row}'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row += 1
        ws[f'A{row}'] = "Project:"
        ws[f'B{row}'] = scan_data.get('project_name', 'Unknown')
        row += 1
        ws[f'A{row}'] = "Scan Types:"
        ws[f'B{row}'] = ", ".join(scan_data.get('scan_types', []))

        # Findings Summary
        row += 2
        ws[f'A{row}'] = "Findings Summary"
        ws[f'A{row}'].font = Font(bold=True, size=14)
        row += 1

        # Headers
        headers = ['Scan Type', 'Total Findings', 'Critical', 'High', 'Medium', 'Low']
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row, col, header)
            cell.fill = header_fill
            cell.font = header_font

        # Data rows
        row += 1
        scan_types = {
            'SAST': scan_data.get('sast_findings', []),
            'SCA': scan_data.get('sca_findings', []),
            'Secrets': scan_data.get('secret_findings', [])
        }

        for scan_type, findings in scan_types.items():
            if findings:
                severity_counts = self._count_by_severity(findings)
                ws.cell(row, 1, scan_type)
                ws.cell(row, 2, len(findings))
                ws.cell(row, 3, severity_counts.get('critical', 0))
                ws.cell(row, 4, severity_counts.get('high', 0))
                ws.cell(row, 5, severity_counts.get('medium', 0))
                ws.cell(row, 6, severity_counts.get('low', 0))
                row += 1

        # Auto-size columns
        for col in range(1, 7):
            ws.column_dimensions[get_column_letter(col)].width = 18

    def _create_vulnerabilities_sheet(self, ws, findings, header_fill, header_font):
        """Create SAST vulnerabilities sheet"""
        headers = ['Title', 'Severity', 'CWE', 'OWASP', 'File', 'Line', 'CVSS', 'Remediation']

        # Add headers
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(1, col, header)
            cell.fill = header_fill
            cell.font = header_font

        # Add data
        for row, finding in enumerate(findings, start=2):
            ws.cell(row, 1, finding.get('title', ''))
            ws.cell(row, 2, finding.get('severity', '').upper())
            ws.cell(row, 3, finding.get('cwe_id', ''))
            ws.cell(row, 4, finding.get('owasp_category', ''))
            ws.cell(row, 5, finding.get('file_path', ''))
            ws.cell(row, 6, finding.get('line_number', ''))
            ws.cell(row, 7, finding.get('cvss_score', ''))
            ws.cell(row, 8, finding.get('remediation', ''))

            # Color code severity
            severity = finding.get('severity', '').lower()
            if severity == 'critical':
                ws.cell(row, 2).fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
                ws.cell(row, 2).font = Font(color="FFFFFF", bold=True)
            elif severity == 'high':
                ws.cell(row, 2).fill = PatternFill(start_color="FF6B6B", end_color="FF6B6B", fill_type="solid")

        # Auto-size columns
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 25

    def _create_dependencies_sheet(self, ws, findings, header_fill, header_font):
        """Create SCA dependencies sheet"""
        headers = ['Package', 'Version', 'Vulnerability', 'CVE', 'Severity', 'CVSS', 'Remediation']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(1, col, header)
            cell.fill = header_fill
            cell.font = header_font

        for row, finding in enumerate(findings, start=2):
            ws.cell(row, 1, finding.get('package', ''))
            ws.cell(row, 2, finding.get('installed_version', ''))
            ws.cell(row, 3, finding.get('vulnerability', ''))
            ws.cell(row, 4, finding.get('cve', ''))
            ws.cell(row, 5, finding.get('severity', '').upper())
            ws.cell(row, 6, finding.get('cvss_score', ''))
            ws.cell(row, 7, finding.get('remediation', ''))

        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 22

    def _create_secrets_sheet(self, ws, findings, header_fill, header_font):
        """Create secrets detection sheet"""
        headers = ['Secret Type', 'Severity', 'File', 'Line', 'Masked Value', 'Remediation']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(1, col, header)
            cell.fill = header_fill
            cell.font = header_font

        for row, finding in enumerate(findings, start=2):
            ws.cell(row, 1, finding.get('secret_type', ''))
            ws.cell(row, 2, finding.get('severity', '').upper())
            ws.cell(row, 3, finding.get('file_path', ''))
            ws.cell(row, 4, finding.get('line_number', ''))
            ws.cell(row, 5, finding.get('masked_value', ''))
            ws.cell(row, 6, finding.get('remediation', ''))

        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 30

    def _create_threat_model_sheet(self, ws, threat_model, header_fill, header_font):
        """Create threat model sheet"""
        headers = ['STRIDE Category', 'Component', 'Threat', 'Description', 'Mitigation']

        for col, header in enumerate(headers, start=1):
            cell = ws.cell(1, col, header)
            cell.fill = header_fill
            cell.font = header_font

        row = 2
        stride_analysis = threat_model.get('stride_analysis', {})
        for category, threats in stride_analysis.items():
            for threat in threats:
                ws.cell(row, 1, category)
                ws.cell(row, 2, threat.get('component', ''))
                ws.cell(row, 3, threat.get('threat', ''))
                ws.cell(row, 4, threat.get('description', ''))
                ws.cell(row, 5, threat.get('mitigation', ''))
                row += 1

        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 28

    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def generate_pdf_report(self, scan_data: Dict[str, Any], output_path: str = None) -> BytesIO:
        """Generate executive PDF report"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=24, textColor=colors.HexColor('#366092'))
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#366092'))

        # Build content
        story = []

        # Title
        story.append(Paragraph("Application Security Scan Report", title_style))
        story.append(Spacer(1, 0.3*inch))

        # Metadata
        metadata = [
            ['Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ['Project:', scan_data.get('project_name', 'Unknown')],
            ['Scan Types:', ', '.join(scan_data.get('scan_types', []))]
        ]
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 0.3*inch))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Spacer(1, 0.2*inch))

        # Summary table
        summary_data = [['Scan Type', 'Total', 'Critical', 'High', 'Medium', 'Low']]
        scan_types = {
            'SAST': scan_data.get('sast_findings', []),
            'SCA': scan_data.get('sca_findings', []),
            'Secrets': scan_data.get('secret_findings', [])
        }

        for scan_type, findings in scan_types.items():
            if findings:
                counts = self._count_by_severity(findings)
                summary_data.append([
                    scan_type,
                    str(len(findings)),
                    str(counts.get('critical', 0)),
                    str(counts.get('high', 0)),
                    str(counts.get('medium', 0)),
                    str(counts.get('low', 0))
                ])

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#366092')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        # Top Vulnerabilities
        if scan_data.get('sast_findings'):
            story.append(Paragraph("Top Critical Vulnerabilities", heading_style))
            story.append(Spacer(1, 0.2*inch))

            critical_vulns = [v for v in scan_data['sast_findings'] if v.get('severity') == 'critical'][:5]
            for vuln in critical_vulns:
                story.append(Paragraph(f"<b>{vuln.get('title')}</b>", styles['Normal']))
                story.append(Paragraph(f"File: {vuln.get('file_path')} (Line {vuln.get('line_number')})", styles['Normal']))
                story.append(Paragraph(f"Remediation: {vuln.get('remediation', 'N/A')}", styles['Normal']))
                story.append(Spacer(1, 0.1*inch))

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        if output_path:
            with open(output_path, 'wb') as f:
                f.write(buffer.getvalue())
            return output_path

        return buffer

    def generate_xml_report(self, scan_data: Dict[str, Any], output_path: str = None) -> str:
        """Generate XML report for tool integration"""
        root = ET.Element('SecurityScanReport')

        # Metadata
        metadata = ET.SubElement(root, 'Metadata')
        ET.SubElement(metadata, 'ReportDate').text = datetime.now().isoformat()
        ET.SubElement(metadata, 'ProjectName').text = scan_data.get('project_name', 'Unknown')
        ET.SubElement(metadata, 'ScanTypes').text = ','.join(scan_data.get('scan_types', []))

        # SAST Findings
        if scan_data.get('sast_findings'):
            sast = ET.SubElement(root, 'SASTFindings', count=str(len(scan_data['sast_findings'])))
            for finding in scan_data['sast_findings']:
                vuln = ET.SubElement(sast, 'Vulnerability')
                ET.SubElement(vuln, 'Title').text = finding.get('title', '')
                ET.SubElement(vuln, 'Severity').text = finding.get('severity', '')
                ET.SubElement(vuln, 'CWE').text = finding.get('cwe_id', '')
                ET.SubElement(vuln, 'OWASP').text = finding.get('owasp_category', '')
                ET.SubElement(vuln, 'FilePath').text = finding.get('file_path', '')
                ET.SubElement(vuln, 'LineNumber').text = str(finding.get('line_number', ''))
                ET.SubElement(vuln, 'CVSSScore').text = str(finding.get('cvss_score', ''))
                ET.SubElement(vuln, 'Remediation').text = finding.get('remediation', '')

        # SCA Findings
        if scan_data.get('sca_findings'):
            sca = ET.SubElement(root, 'SCAFindings', count=str(len(scan_data['sca_findings'])))
            for finding in scan_data['sca_findings']:
                dep = ET.SubElement(sca, 'Dependency')
                ET.SubElement(dep, 'Package').text = finding.get('package', '')
                ET.SubElement(dep, 'Version').text = finding.get('installed_version', '')
                ET.SubElement(dep, 'Vulnerability').text = finding.get('vulnerability', '')
                ET.SubElement(dep, 'CVE').text = finding.get('cve', '')
                ET.SubElement(dep, 'Severity').text = finding.get('severity', '')
                ET.SubElement(dep, 'CVSSScore').text = str(finding.get('cvss_score', ''))

        # Secret Findings
        if scan_data.get('secret_findings'):
            secrets = ET.SubElement(root, 'SecretFindings', count=str(len(scan_data['secret_findings'])))
            for finding in scan_data['secret_findings']:
                secret = ET.SubElement(secrets, 'Secret')
                ET.SubElement(secret, 'Type').text = finding.get('secret_type', '')
                ET.SubElement(secret, 'Severity').text = finding.get('severity', '')
                ET.SubElement(secret, 'FilePath').text = finding.get('file_path', '')
                ET.SubElement(secret, 'LineNumber').text = str(finding.get('line_number', ''))

        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")

        if output_path:
            with open(output_path, 'w') as f:
                f.write(xml_str)
            return output_path

        return xml_str
