# report.py - PDF Report Generation Module for DuCharme Triage Assistant
from collections import Counter
from gui import WINDOWS_EVENT_DESCRIPTIONS, SYSMON_EVENT_DESCRIPTIONS
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.lib.units import inch
from datetime import datetime
import os


# ── Module-level constants ────────────────────────────────────────────────────

_BRAND_BLUE = colors.HexColor('#1e40af')

_RISK_COLORS = {
    "Critical": colors.HexColor('#8B0000'),
    "High":     colors.HexColor('#CC0000'),
    "Medium":   colors.HexColor('#E8650A'),
    "Low":      colors.HexColor('#2E7D32'),
}

_RISK_LABELS = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}

_STANDARD_TABLE_STYLE = TableStyle([
    ("BACKGROUND",     (0, 0), (-1, 0), _BRAND_BLUE),
    ("TEXTCOLOR",      (0, 0), (-1, 0), colors.whitesmoke),
    ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE",       (0, 0), (-1, -1), 9),
    ("GRID",           (0, 0), (-1, -1), 1, colors.black),
    ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ("LEFTPADDING",    (0, 0), (-1, -1), 8),
    ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
    ("TOPPADDING",     (0, 0), (-1, -1), 8),
    ("BOTTOMPADDING",  (0, 0), (-1, 0),  8),
])

_FIELD_LABELS = {
    "timestamp": "Timestamp", "computer": "Computer", "user": "User",
    "added_user": "Added User", "added_by": "Added By",
    "removed_user": "Removed User", "removed_by": "Removed By",
    "deleted_user": "Deleted User", "deleted_by": "Deleted By",
    "process": "Process", "parent_process": "Parent Process",
    "source_image": "Source Image", "target_image": "Target Image",
    "command_line": "Command Line", "src_ip": "Source IP",
    "dest_ip": "Dest IP", "dest_port": "Port", "dns_query": "DNS Query",
    "file_path": "File Path", "logon_type": "Logon Type",
    "task_name": "Task Name", "registry_key": "Registry Key",
    "pipe_name": "Pipe Name", "object_name": "Object Name",
    "image_loaded": "DLL Loaded", "service_name": "Service Name",
    "service_path": "Service Path", "service_account": "Service Account",
    "threat_name": "Threat", "threat_severity": "Severity",
    "action_taken": "Action Taken", "threat_file_path": "Threat File",
    "feature_change": "Protection Change", "config_old_value": "Config Before",
    "config_new_value": "Config After",
    "share_name": "Share", "relative_target": "Pipe / Path",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_event_description(event_id, prefer_sysmon=False):
    """Return a plain-English description for a Windows or Sysmon Event ID."""
    primary   = SYSMON_EVENT_DESCRIPTIONS if prefer_sysmon else WINDOWS_EVENT_DESCRIPTIONS
    secondary = WINDOWS_EVENT_DESCRIPTIONS if prefer_sysmon else SYSMON_EVENT_DESCRIPTIONS
    return primary.get(event_id) or secondary.get(event_id) or "An event was recorded"


def _build_confidence_display(indicator):
    """Return confidence string, annotating boosts: '2/4 -> 3/4 (reason)'."""
    base_conf     = indicator.get('base_confidence', '?')
    actual_conf   = indicator.get('actual_confidence', base_conf)
    boost_reasons = indicator.get('boost_reasons', [])
    if actual_conf > base_conf and boost_reasons:
        return f"{base_conf}/4 -> {actual_conf}/4 ({' + '.join(boost_reasons)})"
    return f"{actual_conf}/4"


def _make_styles(styles):
    """Build and return the shared custom ParagraphStyles used across sections."""
    heading = ParagraphStyle(
        'CustomHeading', parent=styles['Heading1'], fontSize=14,
        textColor=_BRAND_BLUE, spaceAfter=8, spaceBefore=16, keepWithNext=1,
    )
    body   = ParagraphStyle('ReportBody',   parent=styles['BodyText'], fontSize=10, leading=15, spaceAfter=6)
    bullet = ParagraphStyle('ReportBullet', parent=styles['BodyText'], fontSize=10, leading=15, leftIndent=16, spaceAfter=2)
    label  = ParagraphStyle('ReportLabel',  parent=styles['BodyText'], fontSize=10, leading=16, spaceBefore=4)
    return heading, body, bullet, label


# ── Main entry point ──────────────────────────────────────────────────────────

def create_test_pdf(filename="test_report.pdf", file_path=None, results=None,
                    malware_analysis=None, timeline_data=None, incident_context=None,
                    asset_scope=None, deep_dive_data=None, assessment_data=None):
    doc = SimpleDocTemplate(filename, pagesize=LETTER,
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    base_styles = getSampleStyleSheet()
    heading_style, body_style, bullet_style, label_style = _make_styles(base_styles)

    now_str        = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title_style    = ParagraphStyle('CustomTitle',    parent=base_styles['Title'],
                                    fontSize=24, textColor=_BRAND_BLUE, spaceAfter=6,  alignment=1)
    subtitle_style = ParagraphStyle('CustomSubtitle', parent=base_styles['Title'],
                                    fontSize=24, textColor=_BRAND_BLUE, spaceAfter=30, alignment=1)

    story = [
        Paragraph("DuCharme Triage Assistant", title_style),
        Paragraph("Analysis Report", subtitle_style),
        Spacer(1, 0.3 * inch),

    ]

    shared = (heading_style, body_style, bullet_style, label_style, base_styles)

    if malware_analysis:
        story.extend(generate_executive_summary_section(malware_analysis, assessment_data, *shared, section_number=1))
    if file_path and os.path.exists(file_path):
        story.extend(_file_info_section(file_path, heading_style, section_number=2))
    if asset_scope:
        story.extend(generate_asset_scope_section(asset_scope, heading_style, base_styles, section_number=3))
    if incident_context:
        story.extend(generate_incident_context_section(incident_context, heading_style, base_styles, section_number=4))

    sysmon_eids = {e.get('event_id') for e in (results.get('sysmon_events', []) if results else [])}
    if timeline_data and timeline_data.get('chronological_events'):
        story.extend(generate_timeline_section(timeline_data, base_styles, heading_style, section_number=5, sysmon_eids=sysmon_eids))
    if malware_analysis:
        story.extend(generate_indicators_scoring_section(malware_analysis, base_styles, heading_style, section_number=6))
    if deep_dive_data:
        story.extend(generate_deep_dives_section(deep_dive_data, heading_style, base_styles, section_number=7))
    if assessment_data:
        story.append(Spacer(1, 20))
        story.extend(generate_assessment_actions_section(assessment_data, malware_analysis, heading_style, body_style, bullet_style, section_number=8))

    story += [
        Spacer(1, 0.5 * inch),
        Paragraph(f"<i>Generated by DuCharme Triage Assistant on {now_str}</i>", base_styles["Italic"]),
    ]
    doc.build(story)
    return filename


def _file_info_section(file_path, heading_style, section_number=2):
    """Build the File Information section flowables."""
    if os.path.isdir(file_path):
        evtx_files = [os.path.join(file_path, f) for f in os.listdir(file_path) if f.lower().endswith('.evtx')]
        total_kb   = sum(os.path.getsize(f) for f in evtx_files if os.path.isfile(f)) / 1024
        file_name  = os.path.basename(file_path) or file_path
        size_str   = f"{total_kb:.2f} KB ({len(evtx_files)} log file(s))"
        dir_path   = file_path
    else:
        file_name = os.path.basename(file_path)
        dir_path  = os.path.dirname(file_path)
        size_str  = f"{os.path.getsize(file_path) / 1024:.2f} KB"

    _cs = ParagraphStyle('FICell', fontSize=9, leading=13, fontName='Helvetica')
    _hs = ParagraphStyle('FIHdr',  fontSize=9, leading=13, fontName='Helvetica-Bold',
                         textColor=colors.whitesmoke)
    def _p(text, s=_cs):
        safe = (str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\\', '&#92;'))
        return Paragraph(safe, s)

    data = [
        [_p("Property", _hs), _p("Value", _hs)],
        [_p("File Name"),     _p(file_name)],
        [_p("File Path"),     _p(dir_path)],
        [_p("File Size"),     _p(size_str)],
        [_p("Analysis Date"), _p(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))],
    ]
    table = Table(data, colWidths=[1.4*inch, 5.1*inch], splitByRow=False)
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _BRAND_BLUE),
        ("GRID",          (0, 0), (-1, -1), 1, colors.black),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("BACKGROUND",    (0, 1), (-1, -1), colors.beige),
    ]))
    return [Paragraph(f"{section_number}) FILE INFORMATION", heading_style),
            Spacer(1, 8), table, Spacer(1, 0.2 * inch)]


# ── Section generators ────────────────────────────────────────────────────────

def generate_executive_summary_section(malware_analysis, assessment_data,
                                       heading_style, body_style, bullet_style,
                                       label_style, styles, section_number=1):
    """Section 1: Executive Summary."""
    risk_level   = malware_analysis.get('risk_level', 'Unknown')
    highest_conf = malware_analysis.get('highest_confidence', 0)
    indicators   = malware_analysis.get('malware_indicators', [])
    risk_color   = _RISK_COLORS.get(risk_level, colors.black)

    verdict    = {'Critical': 'Likely Malicious', 'High': 'Likely Malicious',
                  'Medium': 'Suspicious', 'Low': 'Likely Benign'}.get(risk_level, 'Undetermined')
    confidence = f"{({4:'High',3:'High',2:'Medium',1:'Low',0:'Low'}.get(highest_conf,'Low'))} ({highest_conf}/4)"
    why_lines  = [ind.get('description', '').strip() for ind in indicators if ind.get('description','').strip()] \
                 or ["No threat indicators matched in the analyzed logs."]
    next_action = ((assessment_data or {}).get('immediate_actions') or ["Review logs manually to determine scope."])[0]
    hex_color   = risk_color.hexval() if hasattr(risk_color, 'hexval') else '000000'

    block = [
        Paragraph(f"{section_number}) EXECUTIVE SUMMARY", heading_style),
        Spacer(1, 10),
        Paragraph(f"<b>Verdict:</b>  <font color='#{hex_color}'>{verdict} ({risk_level})</font>", label_style),
        Paragraph(f"<b>Confidence:</b>  {confidence}", label_style),
        Spacer(1, 6),
        Paragraph("<b>Why:</b>", label_style),
    ]
    block += [Paragraph(f"- {line}", bullet_style) for line in why_lines]
    block += [
        Spacer(1, 6),
        Paragraph(f"<b>Recommended Next Action:</b>  {next_action}", label_style),
        Spacer(1, 6),
        Paragraph(f"<b>Generated On:</b>  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", label_style),
        Spacer(1, 16),
    ]
    return [KeepTogether(block), PageBreak()]


def generate_assessment_actions_section(assessment_data, malware_analysis,
                                        heading_style, body_style, bullet_style,
                                        section_number=8):
    """Section 8: Assessment & Actions."""
    if not assessment_data:
        return [KeepTogether([
            Paragraph(f"{section_number}) ASSESSMENT & ACTIONS", heading_style),
            Spacer(1, 8),
            Paragraph("<i>No assessment data available.</i>", body_style),
            Spacer(1, 16),
        ])]

    risk_level = (malware_analysis or {}).get('risk_level', 'Unknown')
    risk_color = _RISK_COLORS.get(risk_level, colors.black)
    risk_label_style = ParagraphStyle('AssessRisk', parent=body_style,
                                      fontSize=11, textColor=risk_color, spaceAfter=8)
    sub_style = ParagraphStyle('AssessSubHead', parent=body_style,
                               fontSize=11, textColor=_BRAND_BLUE, spaceBefore=8, spaceAfter=4)

    narrative         = assessment_data.get('narrative', [])
    immediate_actions = assessment_data.get('immediate_actions', [])
    followups         = assessment_data.get('followups', [])

    # Anchor: heading + risk level + first narrative paragraph kept together
    # to prevent an orphaned heading. Everything else flows freely.
    anchor = [
        Paragraph(f"{section_number}) ASSESSMENT & ACTIONS", heading_style),
        Spacer(1, 6),
        Paragraph(f"<b>Overall Risk Level: {risk_level}</b>", risk_label_style),
    ]
    if narrative:
        anchor.append(Paragraph(f"<b>{section_number}.1  Assessment</b>", sub_style))
        anchor.append(Paragraph(narrative[0].strip(), body_style))

    content = [KeepTogether(anchor)]

    if narrative:
        content += [Paragraph(p.strip(), body_style) for p in narrative[1:] if p.strip()]
        content.append(Spacer(1, 6))
    if immediate_actions:
        content.append(Paragraph(f"<b>{section_number}.2  Immediate Actions</b>", sub_style))
        content += [Paragraph(f"&#9632;  {a.strip()}", bullet_style) for a in immediate_actions if a.strip()]
        content.append(Spacer(1, 6))
    if followups:
        content.append(Paragraph(f"<b>{section_number}.3  Follow-Ups</b>", sub_style))
        content += [Paragraph(f"&#9632;  {f.strip()}", bullet_style) for f in followups if f.strip()]
        content.append(Spacer(1, 16))

    return content


def generate_asset_scope_section(asset_scope, heading_style, styles, section_number=3):
    """Section 3: Asset & Scope."""
    if not asset_scope:
        return [Paragraph("<i>No asset or scope data available.</i>", styles['BodyText']), Spacer(1, 20)]

    priv_count   = asset_scope.get('privileged_user_count', 0)
    reg_count    = asset_scope.get('regular_user_count', 0)
    users        = asset_scope.get('users_logged_in', 'No user activity detected')
    users_text   = users
    ip_count     = asset_scope.get('ip_count', 0)
    network_ips  = asset_scope.get('network_ips', 'No suspicious external network activity detected')
    network_text = (network_ips + f"<br/><i>({ip_count} total unique IPs detected)</i>") if ip_count > 10 else network_ips
    domains      = asset_scope.get('domains', 'WORKGROUP')
    body_st      = styles['BodyText']

    rows = [
        ["Property", "Value"],
        ["Affected System",         asset_scope.get('hostname', 'Unknown')],
        ["Operating System",        asset_scope.get('os_version', 'Not detected in logs')],
        ["User Accounts",           users_text],
        ["Network Connections",     network_text],
        [f"{'Domain' if domains != 'WORKGROUP' else 'Domain/Workgroup'}:", domains],
        ["How System Was Accessed", asset_scope.get('access_methods', 'No login activity detected')],
        ["Evidence Sources",        asset_scope.get('log_sources', 'Windows Event Logs')],
        ["Analysis Timeframe",      f"{asset_scope.get('analysis_timeframe', 'Unknown')}<br/>"
                                    f"<i>Total Events Analyzed: {asset_scope.get('total_events', 0):,}</i>"],
    ]
    table_data = [[Paragraph(f"<b>{r[0]}</b>", body_st), Paragraph(str(r[1]), body_st)] if i > 0
                  else r for i, r in enumerate(rows)]
    table = Table(table_data, colWidths=[2.2*inch, 4.3*inch], splitByRow=False)
    table.setStyle(_STANDARD_TABLE_STYLE)
    return [KeepTogether([
        Paragraph(f"{section_number}) ASSET & SCOPE", heading_style),
        Spacer(1, 8), table, Spacer(1, 16),
    ])]


def generate_incident_context_section(incident_context, heading_style, styles, section_number=4):
    """Section 4: Incident Context."""
    title   = Paragraph(f"{section_number}) INCIDENT CONTEXT (INPUT)", heading_style)
    body_st = styles['BodyText']
    no_data = Paragraph("<i>No context was entered before report was generated.</i>", body_st)

    if not incident_context:
        return [KeepTogether([title, Spacer(1, 10), no_data, Spacer(1, 20)])]

    context_fields = {
        'reporter': 'How was this incident reported?',
        'observed': 'What was observed?',
        'cause':    'Suspected cause (if known)',
        'impact':   'Impact on business/operations',
    }
    rows = [["Field", "Information"]] + [
        [Paragraph(label, body_st), Paragraph(str(incident_context[key]), body_st)]
        for key, label in context_fields.items() if incident_context.get(key)
    ]
    if len(rows) == 1:
        return [KeepTogether([title, Spacer(1, 8), no_data, Spacer(1, 16)])]

    table = Table(rows, colWidths=[2*inch, 4*inch], splitByRow=False)
    table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), _BRAND_BLUE),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID",           (0, 0), (-1, -1), 1, colors.black),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ("WORDWRAP",       (0, 0), (-1, -1), True),
    ]))
    return [KeepTogether([title, Spacer(1, 8), table, Spacer(1, 16)])]


def generate_timeline_section(timeline_data, styles, heading_style, section_number=5, sysmon_eids=None):
    """Section 5: Timeline Analysis."""
    sysmon_eids   = sysmon_eids or set()
    chronological = timeline_data.get('chronological_events', [])
    grouped       = timeline_data.get('grouped_events', {})

    if not chronological:
        return [KeepTogether([
            Paragraph(f"{section_number}) TIMELINE", heading_style),
            Spacer(1, 8),
            Paragraph("<i>No timeline data available (events may not contain timestamps).</i>", styles['BodyText']),
            Spacer(1, 16),
        ])]

    def eid_label(eid):
        return f"{eid} (Sysmon)" if eid in sysmon_eids else eid

    first, last  = chronological[0]['timestamp'], chronological[-1]['timestamp']
    summary_text = (
        f"<b>Total Events with Timestamps:</b> {len(chronological)}<br/>"
        f"<b>Time Windows (5 min intervals):</b> {len(grouped)}<br/>"
        f"<b>Time Span:</b> {first.strftime('%Y-%m-%d %H:%M')} to {last.strftime('%Y-%m-%d %H:%M')}"
    )

    _shared_tl_style = TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), _BRAND_BLUE),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID",           (0, 0), (-1, -1), 1, colors.black),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("ALIGN",          (0, 0), (0, -1),  "CENTER"),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING",  (0, 0), (-1, 0),  8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ])

    tl_data  = [["#", "Timestamp", "Event ID"]] + [
        [str(i), e['timestamp'].strftime('%Y-%m-%d %H:%M:%S'), eid_label(e['event_id'])]
        for i, e in enumerate(chronological[:15], 1)
    ]
    tl_table = Table(tl_data, colWidths=[0.5*inch, 2.5*inch, 1*inch], splitByRow=False)
    tl_table.setStyle(_shared_tl_style)

    win_small = ParagraphStyle('WindowCell', parent=styles['BodyText'], fontSize=9, leading=11, wordWrap='LTR')
    win_hdr   = ParagraphStyle('WindowHdr',  parent=win_small, textColor=colors.whitesmoke)
    sorted_windows = sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True)[:5]

    win_data = [[Paragraph(f"<b>{h}</b>", win_hdr) for h in ("Rank", "Time Window", "Count", "Top Event IDs")]]
    for i, (window_start, events) in enumerate(sorted_windows, 1):
        top_str = ", ".join(f"{eid_label(eid)} x{c}" for eid, c in Counter(e['event_id'] for e in events).most_common(3))
        win_data.append([
            Paragraph(str(i), win_small),
            Paragraph(window_start.strftime('%Y-%m-%d %H:%M'), win_small),
            Paragraph(str(len(events)), win_small),
            Paragraph(top_str, win_small),
        ])
    win_table = Table(win_data, colWidths=[0.5*inch, 1.5*inch, 0.8*inch, 3.7*inch], splitByRow=False)
    win_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), _BRAND_BLUE),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID",           (0, 0), (-1, -1), 1, colors.black),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("ALIGN",          (0, 0), (0, -1),  "CENTER"),
        ("ALIGN",          (2, 1), (2, -1),  "CENTER"),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING",  (0, 0), (-1, 0),  8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))

    date_range = first.strftime('%Y-%m-%d') if first.date() == last.date() \
                 else f"{first.strftime('%Y-%m-%d')} to {last.strftime('%Y-%m-%d')}"
    return [
        KeepTogether([
            Paragraph(f"{section_number}) TIMELINE ({date_range})", heading_style),
            Spacer(1, 8), Paragraph(summary_text, styles['BodyText']),
            Spacer(1, 10), Paragraph("First 15 Events (Chronological)", styles['Heading3']),
            Spacer(1, 6), tl_table, Spacer(1, 16),
        ]),
        KeepTogether([
            Paragraph("Top 5 Busiest Time Windows", styles['Heading3']),
            Spacer(1, 6), win_table, Spacer(1, 16),
        ]),
    ]


def generate_indicators_scoring_section(malware_analysis_results, styles, heading_style, section_number=6):
    """Section 6: Indicators & Scoring."""
    indicators = malware_analysis_results.get('malware_indicators', [])
    title      = Paragraph(f"{section_number}) INDICATORS & SCORING (SUMMARY)", heading_style)

    if not indicators:
        return [KeepTogether([title, Spacer(1, 10),
                              Paragraph("<i>No malware indicators detected in the analyzed logs.</i>", styles['BodyText']),
                              Spacer(1, 20)])]

    label_style = ParagraphStyle('IndicatorLabel', parent=styles['BodyText'], fontSize=10, leading=14, spaceAfter=2)
    content     = []

    for idx, ind in enumerate(indicators, 1):
        matrix_risk   = ind.get('matrix_risk', 'Unknown')
        risk_color    = _RISK_COLORS.get(matrix_risk, colors.black)
        prefer_sysmon = ind.get('event_type', '') == 'Sysmon'
        eid           = ind['event_id']
        sysmon_tag    = ' (Sysmon)' if prefer_sysmon else ''
        hdr_style     = ParagraphStyle(f'IndHeader{idx}', parent=styles['BodyText'],
                                       fontSize=11, leading=15, textColor=risk_color, spaceBefore=8, spaceAfter=2)
        # For the first indicator, include the section title in the KeepTogether
        # so the heading is never orphaned on a page without any content below it.
        leader = [title, Spacer(1, 10)] if idx == 1 else []
        content.append(KeepTogether(leader + [
            Paragraph(f"<b>{idx}. [{_RISK_LABELS.get(matrix_risk, matrix_risk)}]  {ind.get('threat', ind['description'])}</b>", hdr_style),
            Paragraph(f"<b>Event ID {eid}{sysmon_tag}:</b> {_get_event_description(eid, prefer_sysmon)}", label_style),
            Paragraph(f"<b>Category:</b> {ind['category']}", label_style),
            Paragraph(f"<b>Indicator:</b> {ind['description']}", label_style),
            Paragraph(f"<b>Impact:</b> {ind.get('impact','?')}/4", label_style),
            Paragraph(f"<b>Confidence:</b> {_build_confidence_display(ind)}", label_style),
            Paragraph(f"<b>Evidence:</b> Event ID {eid}{sysmon_tag} occurred {ind['count']} time(s)", label_style),
            Spacer(1, 8),
        ]))

    risk_level    = malware_analysis_results.get('risk_level', 'Unknown')
    summary_style = ParagraphStyle('SummaryText', parent=styles['BodyText'],
                                   fontSize=11, leading=16, textColor=_RISK_COLORS.get(risk_level, colors.black))
    content += [
        Spacer(1, 4),
        Paragraph(
            f"<b>Highest Impact:</b> {malware_analysis_results.get('highest_impact','?')}/4  |  "
            f"<b>Highest Confidence:</b> {malware_analysis_results.get('highest_confidence','?')}/4  ->  "
            f"<b>Overall Risk Level:</b> {risk_level}",
            summary_style
        ),
        Spacer(1, 16),
    ]
    return content


def generate_deep_dives_section(deep_dive_data, heading_style, styles, section_number=7):
    """Section 7: Deep Dives (Evidence) — only renders populated subsections."""
    SKIP_DEDUP    = {"timestamp", "computer"}
    subsections   = [
        ("suspicious_execution", "Suspicious Activity"),
        ("persistence_account",  "Persistence Changes — Account Activity"),
        ("persistence_services", "Persistence Changes — Service Installations"),
        ("credential_dumps",     "Credential Theft & Memory Access"),
        ("credential_logon",     "Logon & Directory Activity"),
        ("network_observations", "Network Observations"),
        ("enumeration",          "Enumeration & Discovery"),
        ("av_protections",       "Malware / AV / OS Protections"),
        ("removable_media",      "Removable Media"),
    ]
    sub_style  = ParagraphStyle('SubHeading',      parent=styles['Heading2'], fontSize=11,
                                textColor=_BRAND_BLUE, spaceBefore=12, spaceAfter=6, keepWithNext=1)
    cell_style    = ParagraphStyle('EvidenceCell',    parent=styles['BodyText'], fontSize=9, leading=12)
    hdr_cell      = ParagraphStyle('EvidenceCellHdr', parent=cell_style, textColor=colors.whitesmoke)
    finding_style = ParagraphStyle('EvidenceFinding', parent=styles['BodyText'], fontSize=9,
                                   leading=13, textColor=colors.HexColor('#374151'), italic=1)

    # Pre-filter: only include sections that will produce at least one visible card.
    # A card is visible if it has >= 2 forensic fields beyond Category/Timestamp/Computer.
    _BOILERPLATE_LABELS = {'Field', 'Timestamp', 'Computer'}  # shared by pre-filter and card filter

    def _has_visible_cards(evidence_list):
        for ev in evidence_list:
            forensic_count = sum(
                1 for field, label in _FIELD_LABELS.items()
                if label not in _BOILERPLATE_LABELS
                and ev.get(field)
                and str(ev[field]).strip().lower() not in ('none', '', '-')
            )
            if forensic_count >= 2:
                return True
        return False

    populated = [
        (key, title) for key, title in subsections
        if deep_dive_data.get(key) and _has_visible_cards(deep_dive_data[key])
    ]

    section_heading = Paragraph(f"{section_number}) DEEP DIVES (EVIDENCE)", heading_style)
    content = []

    for i, (key, title) in enumerate(populated):
        sub_para = Paragraph(f"{section_number}.{i + 1}  {title}", sub_style)
        leader = [section_heading, Spacer(1, 8), sub_para] if i == 0 else [sub_para]

        evidence_list = deep_dive_data[key]
        seen, unique = set(), []
        for ev in evidence_list:
            fp = tuple(sorted(
                (k, str(v)) for k, v in ev.items()
                if k not in SKIP_DEDUP and v and str(v).strip().lower() not in ("none", "", "-")
            ))
            if fp not in seen:
                seen.add(fp)
                unique.append(ev)

        display = unique[:20]
        cards   = []

        for ev in display:
            rows = [[Paragraph("<b>Field</b>", hdr_cell), Paragraph("<b>Value</b>", hdr_cell)]]
            # Category is shown in the subsection heading — omitted from cards.
            for field, label in _FIELD_LABELS.items():
                val = ev.get(field)
                if not val or str(val).strip().lower() in ("none", "", "-"):
                    continue
                display_val = str(val)[:197] + "..." if len(str(val)) > 200 else str(val)
                # Escape special XML characters so ReportLab's markup parser
                # doesn't silently drop backslashes or misinterpret angle brackets
                safe_val = (display_val
                            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                            .replace("\\", "&#92;"))
                rows.append([Paragraph(f"<b>{label}</b>", cell_style), Paragraph(safe_val, cell_style)])
            forensic_rows = [r for r in rows if r[0].text.replace('<b>','').replace('</b>','') not in _BOILERPLATE_LABELS]
            if len(rows) <= 1 or len(forensic_rows) < 2:
                continue
            # Small cards (<=8 rows): never split — splitByRow=False keeps the
            # table whole, and KeepTogether keeps it on one page.
            # Large cards: allow page split with a repeated header row so the
            # analyst always sees the Field/Value header on every page.
            is_small = len(rows) <= 8
            ev_table = Table(
                rows,
                colWidths=[1.6*inch, 4.9*inch],
                splitByRow=not is_small,
                repeatRows=1,
            )
            ev_table.setStyle(_STANDARD_TABLE_STYLE)
            # Always prepend a small Spacer so ReportLab has a natural break
            # point *before* the card rather than being forced to split inside it.
            finding_text = ev.get('_description', '').strip()
            finding_para = (
                [Paragraph(f'<i>{finding_text}</i>', finding_style), Spacer(1, 4)]
                if finding_text else []
            )
            card_items = [Spacer(1, 6), ev_table] + finding_para + [Spacer(1, 6)]
            if is_small:
                cards.append(KeepTogether(card_items))
            else:
                cards.append(card_items)

        if cards:
            # Anchor subsection heading to first card so the heading is never
            # orphaned at the bottom of a page with no content below it.
            first = cards[0]
            if isinstance(first, KeepTogether):
                first_items = list(first._content)
            else:
                first_items = list(first)
            content.append(KeepTogether(leader + [Spacer(1, 6)] + first_items))
            for card in cards[1:]:
                if isinstance(card, KeepTogether):
                    content.append(card)
                else:
                    content.extend(card)
        else:
            content.append(KeepTogether(leader))

        content.append(Spacer(1, 10))

    if not populated:
        content.append(Paragraph("<i>No deep-dive evidence was extracted from the analyzed logs.</i>", styles['BodyText']))
    content.append(Spacer(1, 16))
    return content


if __name__ == "__main__":
    print("=== DuCharme Triage Assistant - Report Generator ===")
    print("Usage: Import and call create_test_pdf() with analysis data.")
