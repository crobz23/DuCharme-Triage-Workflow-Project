# analysis.py - Malware-focused threat analysis engine
"""
DuCharme Triage Assistant - Malware Analysis Engine
Analyzes Windows and Sysmon events for malware indicators and assigns threat scores.


USES CSV FILE for malware indicator definitions
"""

from collections import defaultdict
import csv
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

class MalwareAnalyzer:
    """
    Analyzes event logs for malware-related activity.
    Scores events based on malware threat indicators loaded from CSV.
    """
    
    def __init__(self, malware_csv='malware_indicators.csv', breach_csv='breach_indicators.csv'):
        """
        Initialize the malware analyzer by loading threat mappings from CSV files.
        
        Args:
            malware_csv: Path to the CSV file containing malware indicators
            breach_csv: Path to the CSV file containing breach/account attack indicators
        """
        self.malware_csv_path = malware_csv
        self.breach_csv_path = breach_csv
        self.malware_events = {}
        self.load_all_indicators()
    
    def load_all_indicators(self):
        """Load both malware and breach indicators"""
        print("Loading threat indicators...")
        self.load_indicators_from_csv(self.malware_csv_path, 'malware')
        self.load_indicators_from_csv(self.breach_csv_path, 'breach')
        print(f"✓ Loaded {len(self.malware_events)} total threat indicators")
    
    def load_indicators_from_csv(self, csv_filename, indicator_type):
        """
        Load indicator definitions from CSV file.
        Supports both malware_indicators.csv and breach_indicators.csv formats.
        """
        # Handle PyInstaller bundled resources
        if getattr(sys, 'frozen', False):
            bundle_dir = sys._MEIPASS
            csv_path = os.path.join(bundle_dir, csv_filename)
        else:
            csv_path = csv_filename
        
        if not os.path.exists(csv_path):
            print(f"WARNING: {indicator_type} CSV not found at {csv_path}")
            # Try alternate locations
            alternate_paths = [
                csv_filename,
                f'./{csv_filename}',
                f'../{csv_filename}',
            ]
            
            if getattr(sys, 'frozen', False):
                bundle_dir = sys._MEIPASS
                alternate_paths.insert(0, os.path.join(bundle_dir, csv_filename))
            
            for alt_path in alternate_paths:
                if os.path.exists(alt_path):
                    csv_path = alt_path
                    print(f"Found {indicator_type} CSV at: {alt_path}")
                    break
            else:
                print(f"Skipping {indicator_type} indicators - file not found")
                return
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                loaded_count = 0
                for row in reader:
                    event_id = row['EventID'].strip()
                    
                    # Parse indicators (semicolon separated)
                    indicators_str = row['Indicators'].strip()
                    indicators = [ind.strip() for ind in indicators_str.split(';') if ind.strip()]
                    
                    # Handle both Score and CVSSScore columns
                    score_key = 'Score' if 'Score' in row else 'CVSSScore'
                    score = float(row[score_key].strip())
                    
                    # Create event entry
                    self.malware_events[event_id] = {
                        'description': row['Description'].strip(),
                        'threat': row['Threat'].strip(),
                        'score': score,
                        'category': row['Category'].strip(),
                        'indicators': indicators,
                        'type': indicator_type
                    }
                    loaded_count += 1
                
                print(f"  - Loaded {loaded_count} {indicator_type} indicators")
            
        except Exception as e:
            print(f"Error loading {indicator_type} CSV: {e}")
    
    def analyze_for_malware(self, results):
        """
        Analyze parsed event results for malware indicators.
        
        Args:
            results: Dictionary from parser.analyze_events()
                     Contains: event_ids, counts, sysmon_events, windows_events
        
        Returns:
            Dictionary containing:
                - malware_indicators: List of detected malware-related events (sorted by CVSS score)
                - risk_level: Overall risk assessment based on highest individual score
                - events_by_category: Grouped by MITRE ATT&CK-style categories
                - recommendations: Security recommendations
        """
        
        malware_indicators = []
        events_by_category = defaultdict(list)
        highest_individual_score = 0
        
        # Analyze each event ID found in the logs
        for event_id, count in results['counts'].items():
            if event_id in self.malware_events:
                event_info = self.malware_events[event_id]
                
                # Track highest individual score for risk level
                if event_info['score'] > highest_individual_score:
                    highest_individual_score = event_info['score']
                
                # Create indicator entry
                indicator = {
                    'event_id': event_id,
                    'description': event_info['description'],
                    'threat': event_info['threat'],
                    'count': count,
                    'cvss_score': event_info['score'],
                    'category': event_info['category'],
                    'owasp_category': event_info.get('owasp_category', ''),
                    'indicators_to_check': event_info['indicators']
                }
                
                malware_indicators.append(indicator)
                events_by_category[event_info['category']].append(indicator)
        
        # Sort indicators by CVSS score (highest first) for triage prioritization
        malware_indicators.sort(key=lambda x: x['cvss_score'], reverse=True)
        
        # Determine risk level based on highest individual CVSS score
        risk_level = self._calculate_risk_level_from_cvss(highest_individual_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(events_by_category, risk_level)
        
        return {
            'malware_indicators': malware_indicators,
            'highest_cvss_score': highest_individual_score,
            'risk_level': risk_level,
            'events_by_category': dict(events_by_category),
            'recommendations': recommendations,
            'total_malware_events': len(malware_indicators),
            'total_event_occurrences': sum(ind['count'] for ind in malware_indicators)
        }
    
    def _calculate_risk_level_from_cvss(self, highest_cvss_score):
        """
        Calculate overall risk level based on the highest individual CVSS v3.1 score.
        
        CVSS v3.1 Qualitative Severity Rating Scale:
        - None: 0.0
        - Low: 0.1-3.9
        - Medium: 4.0-6.9
        - High: 7.0-8.9
        - Critical: 9.0-10.0
        
        Returns: String ('Low', 'Medium', 'High', 'Critical')
        """
        if highest_cvss_score == 0.0:
            return 'None'
        elif highest_cvss_score < 4.0:
            return 'Low'
        elif highest_cvss_score < 7.0:
            return 'Medium'
        elif highest_cvss_score < 9.0:
            return 'High'
        else:
            return 'Critical'
    
    def _generate_recommendations(self, events_by_category, risk_level):
        """
        Generate security recommendations based on OWASP best practices.
        Provides actionable guidance aligned with OWASP security principles.
        
        Returns: List of recommendation strings
        """
        recommendations = []
        
        # Risk-level based recommendations (OWASP methodology)
        if risk_level == 'Critical':
            recommendations.append('CRITICAL: Immediate remediation required - Follow OWASP Incident Response guidelines')
            recommendations.append('Isolate affected systems and initiate incident response procedures')
            recommendations.append('Conduct thorough security audit using OWASP testing methodologies')
            recommendations.append('Implement OWASP Proactive Controls to prevent future incidents')
        elif risk_level == 'High':
            recommendations.append('HIGH PRIORITY: Address identified vulnerabilities within 24-48 hours')
            recommendations.append('Review OWASP Top 10 risks applicable to your environment')
            recommendations.append('Implement security logging per OWASP Logging Cheat Sheet')
        elif risk_level == 'Medium':
            recommendations.append('MEDIUM PRIORITY: Schedule remediation within the next sprint/cycle')
            recommendations.append('Review and update security configurations per OWASP guidelines')
            recommendations.append('Implement defense-in-depth strategy')
        else:
            recommendations.append('LOW RISK: Continue monitoring - Maintain security baseline per OWASP ASVS')
            recommendations.append('Regular security assessments recommended')
        
        # OWASP Top 10 2021 category-specific recommendations
        owasp_categories_found = set()
        for events in events_by_category.values():
            for event in events:
                if event.get('owasp_category'):
                    owasp_categories_found.add(event['owasp_category'])
        
        # A01:2021 - Broken Access Control
        if any('A01' in cat for cat in owasp_categories_found):
            recommendations.append('A01 - Broken Access Control: Implement principle of least privilege')
            recommendations.append('A01: Review and enforce access controls on all resources')
            recommendations.append('A01: Enable access control logging and audit regularly')
        
        # A02:2021 - Cryptographic Failures  
        if any('A02' in cat for cat in owasp_categories_found):
            recommendations.append('A02 - Cryptographic Failures: Audit encryption implementations')
            recommendations.append('A02: Ensure data in transit and at rest uses strong encryption (TLS 1.2+)')
            recommendations.append('A02: Review credential storage - use bcrypt/scrypt/Argon2')
        
        # A03:2021 - Injection
        if any('A03' in cat for cat in owasp_categories_found):
            recommendations.append('A03 - Injection: Validate and sanitize all input per OWASP Input Validation Cheat Sheet')
            recommendations.append('A03: Use parameterized queries and prepared statements')
            recommendations.append('A03: Implement command injection prevention controls')
        
        # A05:2021 - Security Misconfiguration
        if any('A05' in cat for cat in owasp_categories_found):
            recommendations.append('A05 - Security Misconfiguration: Review system hardening per CIS benchmarks')
            recommendations.append('A05: Disable unnecessary services and features')
            recommendations.append('A05: Implement security headers and configurations')
        
        # A06:2021 - Vulnerable and Outdated Components
        if any('A06' in cat for cat in owasp_categories_found):
            recommendations.append('A06 - Vulnerable Components: Conduct software inventory and vulnerability scan')
            recommendations.append('A06: Update all software/libraries to latest secure versions')
            recommendations.append('A06: Implement automated dependency checking (OWASP Dependency-Check)')
        
        # A07:2021 - Identification and Authentication Failures
        if any('A07' in cat for cat in owasp_categories_found):
            recommendations.append('A07 - Authentication Failures: Implement MFA on all accounts')
            recommendations.append('A07: Enforce strong password policies (per NIST 800-63B)')
            recommendations.append('A07: Review failed login attempts and implement account lockout')
            recommendations.append('A07: Rotate credentials immediately if compromise suspected')
        
        # A08:2021 - Software and Data Integrity Failures
        if any('A08' in cat for cat in owasp_categories_found):
            recommendations.append('A08 - Integrity Failures: Implement code signing and verification')
            recommendations.append('A08: Use integrity checks for critical files and configurations')
            recommendations.append('A08: Review CI/CD pipeline security (OWASP Top 10 CI/CD Security Risks)')
        
        # A09:2021 - Security Logging and Monitoring Failures
        if any('A09' in cat for cat in owasp_categories_found):
            recommendations.append('A09 - Logging Failures: Enable comprehensive security logging per OWASP Logging Cheat Sheet')
            recommendations.append('A09: Implement SIEM or centralized log management')
            recommendations.append('A09: Create alerts for suspicious activities')
            recommendations.append('A09: Ensure log integrity and retention policies')
        
        # A10:2021 - Server-Side Request Forgery (SSRF)
        if any('A10' in cat for cat in owasp_categories_found):
            recommendations.append('A10 - SSRF: Validate and sanitize all URLs')
            recommendations.append('A10: Implement network segmentation and firewall rules')
            recommendations.append('A10: Disable unused URL schemas (file://, gopher://, etc.)')
        
        # Additional general category-specific recommendations (non-OWASP categories)
        if 'Execution' in events_by_category:
            recommendations.append('Process Execution: Review application whitelisting policies')
            recommendations.append('Execution: Monitor for PowerShell/scripting abuse')
        
        if 'Persistence' in events_by_category:
            recommendations.append('Persistence: Audit scheduled tasks, services, and startup items')
            recommendations.append('Persistence: Review registry auto-run locations')
        
        if 'Command and Control' in events_by_category:
            recommendations.append('C2: Investigate network connections to external IPs')
            recommendations.append('C2: Review DNS queries for suspicious domains')
            recommendations.append('C2: Consider implementing egress filtering')
        
        if 'Defense Evasion' in events_by_category:
            recommendations.append('Defense Evasion: Review anti-malware and EDR logs')
            recommendations.append('Defense Evasion: Check for signs of rootkits or anti-forensics')
        
        if 'Credential Access' in events_by_category:
            recommendations.append('Credential Theft: URGENT - Force password resets for affected accounts')
            recommendations.append('Credential Access: Review privileged account access logs')
        
        if 'Impact' in events_by_category:
            recommendations.append('Impact: WARNING - Data destruction or ransomware indicators detected')
            recommendations.append('Impact: Verify backup integrity and isolation')
        
        # Add general OWASP recommendations
        recommendations.append('General: Follow OWASP Proactive Controls for preventive security')
        recommendations.append('General: Conduct regular security training (OWASP Top 10 awareness)')
        recommendations.append('General: Implement Web Application Firewall (WAF) if applicable')
        
        return recommendations
    
    def get_top_threats(self, analysis_results, top_n=5):
        """
        Get the top N highest-scoring malware threats for triage.
        
        Args:
            analysis_results: Results from analyze_for_malware()
            top_n: Number of top threats to return
        
        Returns:
            List of top threat indicators sorted by CVSS score (highest first)
        """
        indicators = analysis_results['malware_indicators']
        # Already sorted by CVSS score in analyze_for_malware()
        return indicators[:top_n]
    
    def get_category_summary(self, analysis_results):
        """
        Get summary statistics by malware category for triage prioritization.
        
        Args:
            analysis_results: Results from analyze_for_malware()
        
        Returns:
            Dictionary with category names and their highest CVSS scores
        """
        category_summary = {}
        
        for category, events in analysis_results['events_by_category'].items():
            highest_score = max(event['cvss_score'] for event in events)
            event_count = len(events)
            occurrence_count = sum(event['count'] for event in events)
            
            category_summary[category] = {
                'highest_cvss_score': highest_score,
                'unique_events': event_count,
                'total_occurrences': occurrence_count
            }
        
        return category_summary


# Convenience function for quick analysis
def analyze_malware(results, malware_csv='malware_indicators.csv', breach_csv='breach_indicators.csv'):
    """
    Quick wrapper function for malware analysis.
    
    Args:
        results: Dictionary from parser.analyze_events()
        malware_csv: Path to CSV file with malware indicators (default: 'malware_indicators.csv')
        breach_csv: Path to CSV file with breach indicators (default: 'breach_indicators.csv')
    
    Returns:
        Malware analysis results dictionary
    """
    analyzer = MalwareAnalyzer(malware_csv=malware_csv, breach_csv=breach_csv)
    return analyzer.analyze_for_malware(results)

def extract_timeline(events, window_minutes=5):
    """
    Extract timestamps from Windows/Sysmon XML events and build a timeline.

    Args:
        events: List of raw XML event strings
        window_minutes: Time window size for grouping events

    Returns:
        Dictionary containing:
            - chronological_events: Sorted list of events with timestamps
            - grouped_events: Events grouped by time window
    """

    timeline = []

    for raw_event in events:
        try:
            root = ET.fromstring(raw_event)

            # Windows Event XML namespace handling
            time_node = root.find(".//{*}TimeCreated")
            if time_node is None:
                continue

            system_time = time_node.attrib.get("SystemTime")
            if not system_time:
                continue

            timestamp = datetime.fromisoformat(
                system_time.replace("Z", "+00:00")
            )

            event_id_node = root.find(".//{*}EventID")
            event_id = event_id_node.text if event_id_node is not None else "Unknown"

            timeline.append({
                "timestamp": timestamp,
                "event_id": event_id,
                "raw_xml": raw_event
            })

        except ET.ParseError:
            # Skip malformed XML
            continue
        except Exception:
            continue

    # Sort chronologically
    timeline.sort(key=lambda x: x["timestamp"])

    # Group by time windows
    grouped = defaultdict(list)

    for event in timeline:
        window_start = event["timestamp"].replace(
            second=0,
            microsecond=0
        )
        window_start -= timedelta(
            minutes=window_start.minute % window_minutes
        )

        grouped[window_start].append(event)

    return {
        "chronological_events": timeline,
        "grouped_events": dict(grouped)
    }

if __name__ == "__main__":
    print("=== Malware Analysis Engine ===")
    print("This module is designed to be imported and used with actual log file data.")
    print("Usage: from analysis import analyze_malware, extract_timeline")
    print("\nTo use this module:")
    print("1. Parse your log file using parser.py")
    print("2. Pass the results to analyze_malware(results)")
    print("3. View threat analysis with OWASP-based scoring")

