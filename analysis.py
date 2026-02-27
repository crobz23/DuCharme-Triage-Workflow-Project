# analysis.py - Malware-focused threat analysis engine with Impact/Confidence Matrix
"""
DuCharme Triage Assistant - Malware Analysis Engine
Analyzes Windows and Sysmon events for malware indicators using Impact × Confidence matrix.

USES CSV FILES for malware/breach indicator definitions with Impact and BaseConfidence ratings.
"""

from collections import defaultdict
import csv
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

class MalwareAnalyzer:
    """
    Analyzes event logs for malware-related activity using Impact × Confidence matrix.
    Scores events based on threat indicators loaded from CSV with dynamic confidence calculation.
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
        Load indicator definitions from CSV file with Impact and BaseConfidence.
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
                    
                    # Read new Impact and BaseConfidence columns
                    impact = int(row['Impact'].strip())
                    base_confidence = int(row['BaseConfidence'].strip())
                    
                    # Create event entry
                    self.malware_events[event_id] = {
                        'description': row['Description'].strip(),
                        'threat': row['Threat'].strip(),
                        'score': score,  # Keep CVSS for reference
                        'impact': impact,  # NEW: 1-4 scale
                        'base_confidence': base_confidence,  # NEW: 1-4 scale
                        'category': row['Category'].strip(),
                        'indicators': indicators,
                        'type': indicator_type
                    }
                    loaded_count += 1
                
                print(f"  - Loaded {loaded_count} {indicator_type} indicators")
            
        except Exception as e:
            print(f"Error loading {indicator_type} CSV: {e}")
    
    def calculate_dynamic_confidence(self, event_id, base_confidence, count, timeline_data=None):
        """
        Calculate dynamic confidence based on event frequency and clustering.
        
        Args:
            event_id: The Event ID being analyzed
            base_confidence: Starting confidence from CSV (1-4)
            count: How many times this event occurred
            timeline_data: Optional timeline data for clustering detection
        
        Returns:
            tuple: (confidence_level, boost_reasons) where boost_reasons is a list of strings
        """
        confidence = base_confidence
        boost_reasons = []
        
        # Count-based boosting
        if count >= 50:
            confidence = min(4, confidence + 2)  # Lots of events = strong evidence
            boost_reasons.append("high event frequency")
        elif count >= 10:
            confidence = min(4, confidence + 1)  # Moderate frequency
            boost_reasons.append("high event frequency")
        elif count >= 5:
            confidence = min(4, confidence + 1)  # Some repetition
            boost_reasons.append("high event frequency")
        
        # Clustering detection (if timeline data provided)
        if timeline_data and timeline_data.get('grouped_events'):
            grouped = timeline_data['grouped_events']
            # Find maximum events in any single time window for this specific event_id
            if grouped:
                max_window_count = 0
                for window_events in grouped.values():
                    # Count how many events in this window match our event_id
                    event_count = sum(1 for e in window_events if e.get('event_id') == event_id)
                    max_window_count = max(max_window_count, event_count)
                
                if max_window_count >= 20:  # 20+ events of this type in 5-min window = clustered attack
                    if confidence < 4:  # Only boost if not already at max
                        confidence = min(4, confidence + 1)
                        boost_reasons.append("event clustering")
        
        # Cap at maximum confidence level
        return min(4, confidence), boost_reasons
    
    def calculate_risk_from_matrix(self, impact, confidence):
        """
        Calculate risk level using Impact × Confidence matrix (Eric's recommendation).
        
        Args:
            impact: Impact level (1-4)
            confidence: Confidence level (1-4)
        
        Returns:
            str: Risk level ('Low', 'Medium', 'High', or 'Critical')
        
        Matrix:
                     Confidence
                  1      2       3       4
        Impact 1  Low    Med     Med     Med
        Impact 2  Med    Med     High    High
        Impact 3  Med    High    Crit    Crit
        Impact 4  High   Crit    Crit    Crit
        """
        matrix = {
            (1, 1): "Low",
            (1, 2): "Medium",
            (1, 3): "Medium",
            (1, 4): "Medium",
            (2, 1): "Medium",
            (2, 2): "Medium",
            (2, 3): "High",
            (2, 4): "High",
            (3, 1): "Medium",
            (3, 2): "High",
            (3, 3): "Critical",
            (3, 4): "Critical",
            (4, 1): "High",
            (4, 2): "Critical",
            (4, 3): "Critical",
            (4, 4): "Critical",
        }
        
        return matrix.get((impact, confidence), "Unknown")
    
    def analyze_for_malware(self, results, timeline_data=None):
        """
        Analyze parsed event results for malware indicators using Impact × Confidence matrix.
        
        Args:
            results: Dictionary from parser.analyze_events()
                     Contains: event_ids, counts, sysmon_events, windows_events
            timeline_data: Optional timeline data for confidence boosting
        
        Returns:
            Dictionary containing:
                - malware_indicators: List of detected threats (sorted by risk level)
                - risk_level: Overall risk assessment based on highest matrix risk
                - highest_impact: Highest impact value found
                - highest_confidence: Highest confidence value found
                - highest_cvss_score: Kept for reference
                - events_by_category: Grouped by MITRE ATT&CK categories
                - recommendations: Security recommendations
        """
        
        malware_indicators = []
        events_by_category = defaultdict(list)
        highest_individual_score = 0
        highest_impact = 0
        highest_confidence = 0
        
        # Risk priority for sorting
        risk_priority = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Unknown": 0
        }
        highest_risk = "Low"
        highest_risk_priority = 1
        
        # Analyze each event ID found in the logs
        for event_id, count in results['counts'].items():
            if event_id in self.malware_events:
                event_info = self.malware_events[event_id]
                
                # Get base values from CSV
                impact = event_info['impact']
                base_confidence = event_info['base_confidence']
                
                # Calculate dynamic confidence based on frequency and clustering
                actual_confidence, boost_reasons = self.calculate_dynamic_confidence(
                    event_id,
                    base_confidence,
                    count,
                    timeline_data
                )
                
                # Calculate matrix risk
                matrix_risk = self.calculate_risk_from_matrix(impact, actual_confidence)
                
                # Track highest CVSS (for reference)
                if event_info['score'] > highest_individual_score:
                    highest_individual_score = event_info['score']
                
                # Track highest Impact and Confidence
                if impact > highest_impact:
                    highest_impact = impact
                if actual_confidence > highest_confidence:
                    highest_confidence = actual_confidence
                
                # Track highest risk level
                risk_priority_value = risk_priority.get(matrix_risk, 0)
                if risk_priority_value > highest_risk_priority:
                    highest_risk = matrix_risk
                    highest_risk_priority = risk_priority_value
                
                # Create indicator entry with matrix data
                indicator = {
                    'event_id': event_id,
                    'description': event_info['description'],
                    'threat': event_info['threat'],
                    'count': count,
                    'cvss_score': event_info['score'],  # Keep for reference
                    'impact': impact,
                    'base_confidence': base_confidence,
                    'actual_confidence': actual_confidence,
                    'confidence_boosted': actual_confidence > base_confidence,
                    'boost_reasons': boost_reasons,  # NEW: List of boost reasons
                    'matrix_risk': matrix_risk,
                    'category': event_info['category'],
                    'indicators_to_check': event_info['indicators']
                }
                
                malware_indicators.append(indicator)
                events_by_category[event_info['category']].append(indicator)
        
        # Sort indicators by risk level (Critical first), then by impact
        malware_indicators.sort(
            key=lambda x: (
                risk_priority.get(x['matrix_risk'], 0),  # Primary: risk level
                x['impact']  # Secondary: impact
            ),
            reverse=True
        )
        
        # Generate recommendations based on matrix risk
        recommendations = self._generate_recommendations(events_by_category, highest_risk)
        
        return {
            'malware_indicators': malware_indicators,
            'highest_cvss_score': highest_individual_score,  # Kept for reference
            'highest_impact': highest_impact,
            'highest_confidence': highest_confidence,
            'risk_level': highest_risk,  # Now from matrix
            'events_by_category': dict(events_by_category),
            'recommendations': recommendations,
            'total_malware_events': len(malware_indicators),
            'total_event_occurrences': sum(ind['count'] for ind in malware_indicators)
        }
    
    def _generate_recommendations(self, events_by_category, risk_level):
        """
        Generate security recommendations based on matrix risk level and categories.
        
        Args:
            events_by_category: Dictionary of events grouped by category
            risk_level: Overall risk level from matrix ('Low', 'Medium', 'High', 'Critical')
        
        Returns: List of recommendation strings
        """
        recommendations = []
        
        # Risk-level based recommendations
        if risk_level == 'Critical':
            recommendations.append('CRITICAL: Immediate incident response required')
            recommendations.append('Isolate affected systems and initiate containment procedures')
            recommendations.append('Conduct thorough forensic analysis and root cause investigation')
            recommendations.append('Review and strengthen security controls')
        elif risk_level == 'High':
            recommendations.append('HIGH PRIORITY: Address identified threats within 24-48 hours')
            recommendations.append('Investigate suspicious activity and verify system integrity')
            recommendations.append('Implement additional monitoring and detection controls')
        elif risk_level == 'Medium':
            recommendations.append('MEDIUM PRIORITY: Schedule investigation and remediation')
            recommendations.append('Review security configurations and update as needed')
            recommendations.append('Continue monitoring for escalation')
        else:
            recommendations.append('LOW RISK: Continue routine monitoring')
            recommendations.append('Regular security assessments recommended')
        
        # Category-specific recommendations (MITRE ATT&CK based)
        if 'Execution' in events_by_category:
            recommendations.append('Execution: Review application whitelisting and process execution policies')
            recommendations.append('Execution: Monitor for PowerShell/scripting abuse')
        
        if 'Persistence' in events_by_category:
            recommendations.append('Persistence: Audit scheduled tasks, services, and startup items')
            recommendations.append('Persistence: Review registry auto-run locations and WMI subscriptions')
        
        if 'Privilege Escalation' in events_by_category:
            recommendations.append('Privilege Escalation: Review group membership changes immediately')
            recommendations.append('Privilege Escalation: Force password resets for affected accounts')
            recommendations.append('Privilege Escalation: Audit privileged service usage')
        
        if 'Defense Evasion' in events_by_category:
            recommendations.append('Defense Evasion: Check for log tampering and enable tamper protection')
            recommendations.append('Defense Evasion: Review anti-malware and EDR logs for tampering attempts')
            recommendations.append('Defense Evasion: Implement file integrity monitoring')
        
        if 'Credential Access' in events_by_category:
            recommendations.append('Credential Access: Force password resets for all affected accounts')
            recommendations.append('Credential Access: Enable MFA on all privileged accounts immediately')
            recommendations.append('Credential Access: Review authentication logs for unauthorized access')
            recommendations.append('Credential Access: Check for credential dumping tools (mimikatz, etc.)')
        
        if 'Command and Control' in events_by_category:
            recommendations.append('C2: Investigate network connections to external IPs immediately')
            recommendations.append('C2: Review DNS queries for suspicious domains (DGA patterns)')
            recommendations.append('C2: Consider implementing egress filtering and network segmentation')
        
        if 'Lateral Movement' in events_by_category:
            recommendations.append('Lateral Movement: Identify compromised accounts and restrict access')
            recommendations.append('Lateral Movement: Review admin share access and disable if unnecessary')
            recommendations.append('Lateral Movement: Monitor for unusual remote access patterns')
        
        if 'Impact' in events_by_category:
            recommendations.append('Impact: Verify backup integrity and test restoration procedures')
            recommendations.append('Impact: Isolate affected systems to prevent further damage')
            recommendations.append('Impact: Assess scope of data destruction or encryption')
        
        # General recommendations
        recommendations.append('General: Ensure comprehensive security logging is enabled')
        recommendations.append('General: Implement principle of least privilege across all systems')
        
        return recommendations
    
    def get_top_threats(self, analysis_results, top_n=5):
        """
        Get the top N highest-risk malware threats for triage.
        
        Args:
            analysis_results: Results from analyze_for_malware()
            top_n: Number of top threats to return
        
        Returns:
            List of top threat indicators sorted by matrix risk (highest first)
        """
        indicators = analysis_results['malware_indicators']
        # Already sorted by matrix risk in analyze_for_malware()
        return indicators[:top_n]
    
    def get_category_summary(self, analysis_results):
        """
        Get summary statistics by category for triage prioritization.
        
        Args:
            analysis_results: Results from analyze_for_malware()
        
        Returns:
            Dictionary with category names and their highest risk levels
        """
        category_summary = {}
        
        risk_priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
        
        for category, events in analysis_results['events_by_category'].items():
            # Find highest risk in this category
            highest_risk = "Low"
            highest_priority = 1
            
            for event in events:
                risk = event['matrix_risk']
                priority = risk_priority.get(risk, 0)
                if priority > highest_priority:
                    highest_risk = risk
                    highest_priority = priority
            
            event_count = len(events)
            occurrence_count = sum(event['count'] for event in events)
            
            category_summary[category] = {
                'highest_risk': highest_risk,
                'highest_cvss_score': max(event['cvss_score'] for event in events),
                'unique_events': event_count,
                'total_occurrences': occurrence_count
            }
        
        return category_summary


# Convenience function for quick analysis
def analyze_malware(results, timeline_data=None, malware_csv='malware_indicators.csv', breach_csv='breach_indicators.csv'):
    """
    Quick wrapper function for malware analysis with Impact × Confidence matrix.
    
    Args:
        results: Dictionary from parser.analyze_events()
        timeline_data: Optional timeline data for confidence boosting
        malware_csv: Path to CSV file with malware indicators (default: 'malware_indicators.csv')
        breach_csv: Path to CSV file with breach indicators (default: 'breach_indicators.csv')
    
    Returns:
        Malware analysis results dictionary with matrix risk scoring
    """
    analyzer = MalwareAnalyzer(malware_csv=malware_csv, breach_csv=breach_csv)
    return analyzer.analyze_for_malware(results, timeline_data)

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
    print("=== Malware Analysis Engine with Impact × Confidence Matrix ===")
    print("This module uses Eric's recommended matrix system for context-aware risk scoring.")
    print("Usage: from analysis import analyze_malware, extract_timeline")
    print("\nTo use this module:")
    print("1. Parse your log file using parser.py")
    print("2. Extract timeline using extract_timeline(events)")
    print("3. Pass both to analyze_malware(results, timeline_data)")
    print("4. View threat analysis with Impact × Confidence matrix scoring")

