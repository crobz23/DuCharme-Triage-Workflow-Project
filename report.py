# report.py - PDF Report Generation Module for DuCharme Triage Assistant
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.lib.units import inch
from datetime import datetime
import os


def _truncate(text, max_chars=500, label=""):
    """
    Truncate a string to max_chars to prevent ReportLab table cells
    from exceeding the page height.
    """
    if not text:
        return text or ""
    text = str(text)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + " [character limit reached]"


def create_test_pdf(filename="test_report.pdf", file_path=None, results=None, malware_analysis=None, timeline_data=None, incident_context=None, asset_scope=None):
    """
    Create a PDF report for the DuCharme Triage Assistant.
    
    Args:
        filename: Output PDF filename
        file_path: Path to the analyzed log file
        results: Analysis results dictionary from parser
        malware_analysis: Malware analysis results from analysis.py
        timeline_data: Timeline analysis results from analysis.py
        incident_context: Incident context information from GUI dialog
        asset_scope: Asset and scope information from GUI
    
    Returns:
        str: Path to the generated PDF file
    """
    # Create the document
    doc = SimpleDocTemplate(
        filename,
        pagesize=LETTER,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )
    
    styles = getSampleStyleSheet()
    story = []
    
    # Add custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=6,
        alignment=1  # Center
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=30,
        alignment=1  # Center
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=8,
        spaceBefore=16,
        keepWithNext=1,
    )
    
    # Title (two centered lines)
    title = Paragraph("DuCharme Triage Assistant", title_style)
    story.append(title)
    subtitle = Paragraph("Analysis Report", subtitle_style)
    story.append(subtitle)
    story.append(Spacer(1, 0.3 * inch))
    
    # Report Generated timestamp
    report_info = Paragraph(
        f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
        styles["BodyText"]
    )
    story.append(report_info)
    story.append(Spacer(1, 0.3 * inch))
    
    # === SECTION 1: FILE INFORMATION ===
    if file_path and os.path.exists(file_path):
        # Get directory path without filename
        directory_path = os.path.dirname(file_path)
        
        file_info_data = [
            ["Property", "Value"],
            ["File Name", os.path.basename(file_path)],
            ["File Path", directory_path],
            ["File Size", f"{os.path.getsize(file_path) / 1024:.2f} KB"],
            ["Analysis Date", datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        
        file_table = Table(file_info_data, colWidths=[2*inch, 4*inch], splitByRow=False)
        file_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ])
        )
        story.append(Paragraph("1) FILE INFORMATION", heading_style))
        story.append(Spacer(1, 8))
        story.append(file_table)
        story.append(Spacer(1, 0.2 * inch))
    
    # === SECTION 2: ASSET & SCOPE ===
    if asset_scope:
        asset_scope_section = generate_asset_scope_section(asset_scope, heading_style, styles, section_number=2)
        story.extend(asset_scope_section)
    
    # === SECTION 3: INCIDENT CONTEXT ===
    if incident_context:
        incident_context_section = generate_incident_context_section(incident_context, heading_style, styles, section_number=3)
        story.extend(incident_context_section)
    
    # === SECTION 4: TIMELINE ANALYSIS ===
    if timeline_data and timeline_data.get('chronological_events'):
        timeline_section = generate_timeline_section(timeline_data, styles, heading_style, section_number=4)
        story.extend(timeline_section)
    
    # === SECTION 5: INDICATORS & SCORING ===
    if malware_analysis:
        indicators_section = generate_indicators_scoring_section(malware_analysis, styles, heading_style, section_number=5)
        story.extend(indicators_section)
    
    # Footer
    story.append(Spacer(1, 0.5 * inch))
    footer = Paragraph(
        f"<i>Generated by DuCharme Triage Assistant on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
        styles["Italic"],
    )
    story.append(footer)
    
    # Build the PDF
    doc.build(story)
    
    return filename


def generate_timeline_section(timeline_data, styles, heading_style, section_number=4):
    section_content = []

    chronological = timeline_data.get('chronological_events', [])
    grouped = timeline_data.get('grouped_events', {})

    if not chronological:
        section_content.append(KeepTogether([
            Paragraph(f"{section_number}) TIMELINE (LAST N DAYS)", heading_style),
            Spacer(1, 8),
            Paragraph("<i>No timeline data available (events may not contain timestamps).</i>", styles['BodyText']),
            Spacer(1, 16),
        ]))
        return section_content

    summary_text = (
        f"<b>Total Events with Timestamps:</b> {len(chronological)}<br/>"
        f"<b>Time Windows (5 min intervals):</b> {len(grouped)}<br/>"
        f"<b>Time Span:</b> {chronological[0]['timestamp'].strftime('%Y-%m-%d %H:%M')} to "
        f"{chronological[-1]['timestamp'].strftime('%Y-%m-%d %H:%M')}"
    )

    # First 15 events table
    timeline_table_data = [["#", "Timestamp", "Event ID"]]
    for i, event in enumerate(chronological[:15], 1):
        timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        timeline_table_data.append([str(i), timestamp_str, event['event_id']])

    timeline_table = Table(timeline_table_data, colWidths=[0.5*inch, 2.5*inch, 1*inch], splitByRow=False)
    timeline_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ])
    )

    section_content.append(KeepTogether([
        Paragraph(f"{section_number}) TIMELINE (LAST N DAYS)", heading_style),
        Spacer(1, 8),
        Paragraph(summary_text, styles['BodyText']),
        Spacer(1, 10),
        Paragraph("First 15 Events (Chronological)", styles['Heading3']),
        Spacer(1, 6),
        timeline_table,
        Spacer(1, 16),
    ]))

    # Top 5 busiest time windows
    sorted_windows = sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True)[:5]

    window_table_data = [["Rank", "Time Window", "Event Count", "Top Event IDs"]]
    for i, (window_start, events) in enumerate(sorted_windows, 1):
        window_str = window_start.strftime('%Y-%m-%d %H:%M')
        event_count = len(events)
        from collections import Counter
        event_counts = Counter(e['event_id'] for e in events)
        top_events = event_counts.most_common(3)
        top_events_str = ", ".join([f"{eid}({count})" for eid, count in top_events])
        window_table_data.append([str(i), window_str, str(event_count), top_events_str])

    window_table = Table(window_table_data, colWidths=[0.5*inch, 1.5*inch, 1*inch, 2.5*inch], splitByRow=False)
    window_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 1), (2, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ])
    )

    section_content.append(KeepTogether([
        Paragraph("Top 5 Busiest Time Windows", styles['Heading3']),
        Spacer(1, 6),
        window_table,
        Spacer(1, 16),
    ]))

    return section_content


def generate_asset_scope_section(asset_scope, heading_style, styles, section_number=2):
    """
    Generate Asset & Scope section for the PDF report.
    Professional format suitable for non-technical stakeholders.
    
    Args:
        asset_scope: Dictionary from GUI's get_asset_scope_summary()
        heading_style: Style for section headings
        styles: ReportLab styles object
        section_number: Section number to display
    
    Returns:
        List of ReportLab flowables for the asset scope section
    """
    section_content = []

    if not asset_scope:
        no_data_text = Paragraph(
            "<i>No asset or scope data available.</i>",
            styles['BodyText']
        )
        section_content.append(no_data_text)
        section_content.append(Spacer(1, 20))
        return section_content
    
    # Create professional summary table
    summary_data = [["Property", "Value"]]
    
    # Hostname
    hostname = _truncate(asset_scope.get('hostname', 'Unknown'), 100)
    summary_data.append([
        Paragraph("<b>Affected System:</b>", styles['BodyText']),
        Paragraph(hostname, styles['BodyText'])
    ])

    # OS / Version / Patch Level
    os_version = _truncate(asset_scope.get('os_version', 'Not detected in logs'), 100)
    summary_data.append([
        Paragraph("<b>Operating System:</b>", styles['BodyText']),
        Paragraph(os_version, styles['BodyText'])
    ])

    # User Accounts
    users = asset_scope.get('users_logged_in', 'No user activity detected')
    priv_count = asset_scope.get('privileged_user_count', 0)
    reg_count = asset_scope.get('regular_user_count', 0)

    if priv_count > 0 or reg_count > 0:
        total_users = priv_count + reg_count
        context_text = f"<i>{total_users} unique user account(s) detected</i><br/>{_truncate(users, 500)}"
    else:
        context_text = _truncate(users, 500)

    summary_data.append([
        Paragraph("<b>User Accounts:</b>", styles['BodyText']),
        Paragraph(context_text, styles['BodyText'])
    ])

    # Network / IP Addresses
    network_ips = asset_scope.get('network_ips', 'No external network activity detected')
    ip_count = asset_scope.get('ip_count', 0)

    if ip_count > 0:
        network_text = _truncate(network_ips, 400)
        if ip_count > 10:
            network_text += f"<br/><i>({ip_count} total unique IPs detected)</i>"
    else:
        network_text = _truncate(network_ips, 400)

    summary_data.append([
        Paragraph("<b>Network Connections:</b>", styles['BodyText']),
        Paragraph(network_text, styles['BodyText'])
    ])

    # Domain
    domains = _truncate(asset_scope.get('domains', 'WORKGROUP'), 100)
    domain_label = "Domain:" if domains != 'WORKGROUP' else "Domain/Workgroup:"
    summary_data.append([
        Paragraph(f"<b>{domain_label}</b>", styles['BodyText']),
        Paragraph(domains, styles['BodyText'])
    ])

    # Access Methods
    access_methods = _truncate(asset_scope.get('access_methods', 'No login activity detected'), 400)
    summary_data.append([
        Paragraph("<b>How System Was Accessed:</b>", styles['BodyText']),
        Paragraph(access_methods, styles['BodyText'])
    ])

    # Evidence Sources
    log_sources = _truncate(asset_scope.get('log_sources', 'Windows Event Logs'), 400)
    summary_data.append([
        Paragraph("<b>Evidence Sources:</b>", styles['BodyText']),
        Paragraph(log_sources, styles['BodyText'])
    ])

    # Analysis Timeframe
    timeframe = _truncate(asset_scope.get('analysis_timeframe', 'Unknown'), 150)
    total_events = asset_scope.get('total_events', 0)
    runtime_text = f"{timeframe}<br/><i>Total Events Analyzed: {total_events:,}</i>"
    summary_data.append([
        Paragraph("<b>Analysis Timeframe:</b>", styles['BodyText']),
        Paragraph(runtime_text, styles['BodyText'])
    ])
    
    # Create the table
    summary_table = Table(summary_data, colWidths=[2.2*inch, 4.3*inch], splitByRow=False)
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )

    section_content.append(KeepTogether([
        Paragraph(f"{section_number}) ASSET & SCOPE", heading_style),
        Spacer(1, 8),
        summary_table,
        Spacer(1, 16),
    ]))

    return section_content


def generate_incident_context_section(incident_context, heading_style, styles, section_number=3):
    """
    Generate Incident Context section for the PDF report.
    
    Args:
        incident_context: Dictionary containing incident context information
        heading_style: Style for section headings
        styles: ReportLab styles object
        section_number: Section number to display
    
    Returns:
        List of ReportLab flowables for the incident context section
    """
    section_content = []

    if not incident_context:
        section_content.append(KeepTogether([
            Paragraph(f"{section_number}) INCIDENT CONTEXT (INPUT)", heading_style),
            Spacer(1, 10),
            Paragraph("<i>No incident context information provided.</i>", styles['BodyText']),
            Spacer(1, 20),
        ]))
        return section_content
    
    context_data = [["Field", "Information"]]
    
    # Add incident context fields - MATCHES GUI field names (reporter, observed, cause, impact)
    context_fields = {
        'reporter': 'How was this incident reported?',
        'observed': 'What was observed?',
        'cause': 'Suspected cause (if known)',
        'impact': 'Impact on business/operations'
    }
    
    for field_key, field_label in context_fields.items():
        if incident_context.get(field_key):
            value = _truncate(str(incident_context[field_key]), 500)
            context_data.append([Paragraph(field_label, styles['BodyText']), Paragraph(value, styles['BodyText'])])
    
    if len(context_data) > 1:  # Has data beyond header
        context_table = Table(context_data, colWidths=[2*inch, 4*inch], splitByRow=False)
        context_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ])
        )
        section_content.append(KeepTogether([
            Paragraph(f"{section_number}) INCIDENT CONTEXT (INPUT)", heading_style),
            Spacer(1, 8),
            context_table,
            Spacer(1, 16),
        ]))
    else:
        section_content.append(KeepTogether([
            Paragraph(f"{section_number}) INCIDENT CONTEXT (INPUT)", heading_style),
            Spacer(1, 8),
            Paragraph("<i>No incident context data available.</i>", styles['BodyText']),
            Spacer(1, 16),
        ]))

    return section_content


def _get_event_description(event_id, prefer_sysmon=False):
    """
    Return a plain-English description for a Windows or Sysmon Event ID.
    Pass prefer_sysmon=True for indicators sourced from the malware/Sysmon CSV
    so that overlapping IDs (e.g. 10) resolve to the Sysmon meaning.
    """
    windows_events = {
        '1': 'A system error occurred',
        '6': 'A driver was loaded',
        '7': 'A service was started or stopped',
        '10': 'A COM+ catalog error occurred',
        '11': 'A disk controller error was detected',
        '12': 'The Service Control Manager started',
        '13': 'The Service Control Manager stopped',
        '15': 'A disk device error occurred',
        '41': 'The computer restarted unexpectedly',
        '42': 'The computer is entering sleep mode',
        '51': 'A disk paging error occurred',
        '55': 'A file system corruption was detected',
        '104': 'The System log was cleared',
        '107': 'The computer woke up from sleep',
        '109': 'A kernel power transition occurred',
        '1001': 'A Windows Error Reporting crash occurred',
        '1014': 'A DNS client resolution timeout occurred',
        '1100': 'Event logging was shut down',
        '1101': 'Audit events were dropped',
        '1102': 'The Security audit log was cleared',
        '1530': 'A user profile could not be loaded',
        '6005': 'The Event Log service started',
        '6006': 'The Event Log service stopped',
        '6008': 'An unexpected system shutdown occurred',
        '6009': 'System boot information was logged',
        '6013': 'System uptime was recorded',
        '7000': 'A service failed to start',
        '7001': 'A service depends on another service that failed',
        '7009': 'A service timeout occurred during startup',
        '7011': 'A service timeout occurred during operation',
        '7022': 'A service hung on starting',
        '7023': 'A service terminated with an error',
        '7024': 'A service terminated with a service-specific error',
        '7026': 'A boot-start or system-start driver failed to load',
        '7030': 'A service was configured incorrectly',
        '7031': 'A service terminated unexpectedly',
        '7032': 'The Service Control Manager attempted corrective action',
        '7034': 'A service crashed unexpectedly',
        '7035': 'A service control was sent',
        '7036': 'A service entered running or stopped state',
        '7040': 'A service startup type was changed',
        '7045': 'A new service was installed',
        '4103': 'A PowerShell script was executed',
        '4104': 'A PowerShell command was executed',
        '4105': 'A PowerShell script started',
        '4106': 'A PowerShell script stopped',
        '4616': 'The system time was changed',
        '4624': 'A user successfully logged in',
        '4625': 'A user failed to log in',
        '4634': 'A user session ended',
        '4647': 'A user logged out',
        '4648': 'A user logged in with different credentials',
        '4656': 'A file or folder was accessed',
        '4657': 'A system setting was changed',
        '4663': 'A file or folder was accessed',
        '4670': 'File or folder permissions were changed',
        '4672': 'A user was given special access rights',
        '4673': 'A privileged operation was attempted',
        '4688': 'A program was started',
        '4689': 'A program was closed',
        '4698': 'A scheduled task was created',
        '4699': 'A scheduled task was deleted',
        '4700': 'A scheduled task was enabled',
        '4701': 'A scheduled task was disabled',
        '4702': 'A scheduled task was updated',
        '4719': 'An audit policy was changed',
        '4720': 'A user account was created',
        '4722': 'A user account was enabled',
        '4723': 'A password change was attempted',
        '4724': 'A password reset was attempted',
        '4725': 'A user account was disabled',
        '4726': 'A user account was deleted',
        '4728': 'A user was added to a global security group',
        '4732': 'A user was added to a local security group',
        '4733': 'A user was removed from a group',
        '4735': 'A security group was changed',
        '4737': 'A global security group was changed',
        '4738': 'A user account was modified',
        '4740': 'A user account was locked',
        '4755': 'A universal security group was changed',
        '4756': 'A user was added to a universal group',
        '4757': 'A user was removed from a universal group',
        '4765': 'A security identifier history was added',
        '4767': 'A user account was unlocked',
        '4768': 'A Kerberos login ticket was requested',
        '4769': 'A Kerberos service ticket was requested',
        '4771': 'A Kerberos pre-authentication failed',
        '4776': 'A login attempt was validated',
        '4778': 'A remote session was reconnected',
        '4779': 'A remote session was disconnected',
        '4794': 'A password recovery mode was attempted',
        '5136': 'A directory object was modified',
        '5137': 'A directory object was created',
        '5140': 'A network folder was accessed',
        '5141': 'A directory object was deleted',
        '5142': 'A network folder was shared',
        '5145': 'A network folder access was checked',
    }

    sysmon_events = {
        '1': 'A process was created',
        '2': 'A file creation timestamp was modified',
        '3': 'A network connection was initiated by a process',
        '4': 'Sysmon service state changed',
        '5': 'A process was terminated',
        '6': 'A driver was loaded into the kernel',
        '7': 'A DLL or library file was loaded by a process',
        '8': 'A process injected code into another process',
        '9': 'A process performed raw disk access',
        '10': 'A process opened another process\'s memory',
        '11': 'A file was created on disk',
        '12': 'A registry key or value was created or deleted',
        '13': 'A registry value was modified',
        '14': 'A registry key or value was renamed',
        '15': 'A file alternate data stream was created',
        '16': 'Sysmon configuration was changed',
        '17': 'A named pipe was created',
        '18': 'A named pipe connection was made',
        '19': 'A WMI event filter was registered',
        '20': 'A WMI event consumer was registered',
        '21': 'A WMI consumer was bound to a filter',
        '22': 'A DNS query was made by a process',
        '23': 'A file was deleted',
        '24': 'Clipboard contents were read by a process',
        '25': 'A process image was tampered with',
        '26': 'A file deletion was detected and logged',
        '27': 'A blocked executable was prevented from running',
        '28': 'A file shred attempt was blocked',
        '29': 'An executable file was detected on disk',
    }

    if prefer_sysmon:
        if event_id in sysmon_events:
            return sysmon_events[event_id]
        elif event_id in windows_events:
            return windows_events[event_id]
    else:
        if event_id in windows_events:
            return windows_events[event_id]
        elif event_id in sysmon_events:
            return sysmon_events[event_id]

    return "An event was recorded"


def _get_risk_color(matrix_risk):
    """Return a color for a given matrix risk level."""
    return {
        "Critical": colors.HexColor('#8B0000'),  # dark red
        "High":     colors.HexColor('#CC0000'),  # bright red
        "Medium":   colors.HexColor('#B8860B'),  # dark goldenrod - readable on white
        "Low":      colors.HexColor('#2E7D32'),  # green
    }.get(matrix_risk, colors.black)


def _build_confidence_display(indicator):
    """
    Mirror the GUI confidence display logic exactly.
    Returns a plain string like:
      '2/4 → 3/4 (high event frequency)'  (boosted)
      '3/4'                                 (not boosted)
    """
    base_conf   = indicator.get('base_confidence', '?')
    actual_conf = indicator.get('actual_confidence', base_conf)
    boost_reasons = indicator.get('boost_reasons', [])

    if actual_conf > base_conf and boost_reasons:
        reason_text = " + ".join(boost_reasons)
        return f"{base_conf}/4 → {actual_conf}/4 ({reason_text})"
    return f"{actual_conf}/4"


def generate_indicators_scoring_section(malware_analysis_results, styles, heading_style, section_number=5):
    """
    Generate Indicators & Scoring section for malware events.
    Displays Impact / Confidence scores (replacing CVSS) and mirrors the
    GUI's confidence-boost annotation format.

    Args:
        malware_analysis_results: Dictionary from MalwareAnalyzer.analyze_for_malware()
        styles: ReportLab styles object
        heading_style: Style for section headings
        section_number: Section number to display

    Returns:
        List of ReportLab flowables (Paragraphs, Tables, Spacers) for the section
    """
    section_content = []

    # Indicators already sorted by matrix risk (Critical first) from analysis.py
    indicators = malware_analysis_results.get('malware_indicators', [])

    if not indicators:
        section_content.append(KeepTogether([
            Paragraph(f"{section_number}) INDICATORS & SCORING (SUMMARY)", heading_style),
            Spacer(1, 10),
            Paragraph("<i>No malware indicators detected in the analyzed logs.</i>", styles['BodyText']),
            Spacer(1, 20),
        ]))
        return section_content

    # ── Section heading ───────────────────────────────────────────────────────
    section_content.append(Paragraph(f"{section_number}) INDICATORS & SCORING (SUMMARY)", heading_style))
    section_content.append(Spacer(1, 10))

    # ── Per-indicator blocks ──────────────────────────────────────────────────
    label_style = ParagraphStyle(
        'IndicatorLabel',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14,
        spaceAfter=2,
    )

    risk_icons = {
        "Critical": "CRITICAL",
        "High":     "HIGH",
        "Medium":   "MEDIUM",
        "Low":      "LOW",
    }

    for idx, indicator in enumerate(indicators, 1):
        matrix_risk    = indicator.get('matrix_risk', 'Unknown')
        impact         = indicator.get('impact', '?')
        conf_display   = _build_confidence_display(indicator)
        risk_label     = risk_icons.get(matrix_risk, matrix_risk)
        risk_color     = _get_risk_color(matrix_risk)
        base_conf      = indicator.get('base_confidence', '?')
        actual_conf    = indicator.get('actual_confidence', base_conf)
        eid            = indicator['event_id']
        # Event IDs 1-29 are Sysmon-range and overlap with Windows System IDs.
        # For malware indicators these low IDs are always Sysmon events.
        prefer_sysmon  = eid.isdigit() and 1 <= int(eid) <= 29
        eid_desc       = _get_event_description(eid, prefer_sysmon=prefer_sysmon)

        header_style = ParagraphStyle(
            f'IndHeader{idx}',
            parent=styles['BodyText'],
            fontSize=11,
            leading=15,
            textColor=risk_color,
            spaceBefore=8,
            spaceAfter=2,
        )

        # Build all lines for this indicator and wrap in KeepTogether
        block = [
            Paragraph(
                f"<b>{idx}. [{risk_label}]  {_truncate(indicator.get('threat', indicator['description']), 120)}</b>",
                header_style
            ),
            Paragraph(f"<b>Event ID {eid}:</b> {eid_desc}", label_style),
            Paragraph(f"<b>Category:</b> {_truncate(indicator['category'], 100)}", label_style),
            Paragraph(f"<b>Indicator:</b> {_truncate(indicator["description"], 400)}", label_style),
            Paragraph(f"<b>Impact:</b> {impact}/4", label_style),
            Paragraph(f"<b>Confidence:</b> {conf_display}", label_style),
            Paragraph(
                f"<b>Evidence:</b> Event ID {eid} occurred {indicator['count']} time(s)",
                label_style
            ),
            Spacer(1, 8),
        ]
        section_content.append(KeepTogether(block))

    # ── Overall summary bar ───────────────────────────────────────────────────
    section_content.append(Spacer(1, 4))

    highest_impact     = malware_analysis_results.get('highest_impact', '?')
    highest_confidence = malware_analysis_results.get('highest_confidence', '?')
    risk_level         = malware_analysis_results.get('risk_level', 'Unknown')

    summary_style = ParagraphStyle(
        'SummaryText',
        parent=styles['BodyText'],
        fontSize=11,
        leading=16,
        textColor=_get_risk_color(risk_level),
    )

    section_content.append(Paragraph(
        f"<b>Highest Impact:</b> {highest_impact}/4  |  "
        f"<b>Highest Confidence:</b> {highest_confidence}/4  →  "
        f"<b>Overall Risk Level:</b> {risk_level}",
        summary_style
    ))
    section_content.append(Spacer(1, 16))

    return section_content


if __name__ == "__main__":
    print("=== DuCharme Triage Assistant - Report Generator ===")
    print("This module generates PDF reports from log analysis.")
    print("Usage: Import and call create_test_pdf() with analysis data.")
