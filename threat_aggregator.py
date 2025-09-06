#!/usr/bin/env python3
"""
Threat Intelligence Automation Script
=====================================

A comprehensive threat intelligence aggregation tool that fetches, parses, and 
consolidates Indicators of Compromise (IOCs) from multiple public threat feeds.
"""

import csv
import datetime
import re
import requests
import sys
from collections import defaultdict, Counter
from io import StringIO
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlparse
import time

# =============================================================================
# CONFIGURATION SECTION
# =============================================================================

# Threat Intelligence Feed Configuration
# This centralized configuration makes it easy to add/modify feeds without
# changing the core logic throughout the codebase
THREAT_FEEDS = {
    'feodo_tracker': {
        'name': 'Feodo Tracker C2 Botnet IPs',
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
        'type': 'ip_addresses',
        'description': 'Known C2 botnet IP addresses from Feodo Tracker'
    },
    'urlhaus_recent': {
        'name': 'URLhaus Recent Malware URLs',
        'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
        'type': 'malware_urls',
        'description': 'Recent malware-associated URLs from URLhaus'
    }
}

# HTTP Configuration
HTTP_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 2   # seconds between retries

# Output Configuration
REPORT_FILENAME_FORMAT = "threat_report_{timestamp}.md"
TIMESTAMP_FORMAT = "%Y-%m-%d_%H%M%S"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a properly formatted IPv4 address.
    
    Args:
        ip (str): IP address string to validate
        
    Returns:
        bool: True if valid IPv4 address, False otherwise
    """
    try:
        # Split IP into octets and validate each one
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        
        for octet in octets:
            # Check if octet is numeric and within valid range (0-255)
            if not octet.isdigit() or not 0 <= int(octet) <= 255:
                return False
        return True
    except (AttributeError, ValueError):
        return False


def validate_url(url: str) -> bool:
    """
    Validate if a string is a properly formatted URL.
    
    Args:
        url (str): URL string to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        # URL must have both scheme (http/https) and netloc (domain)
        return all([result.scheme, result.netloc])
    except (AttributeError, ValueError):
        return False


def get_current_timestamp() -> str:
    """
    Generate a formatted timestamp for report naming and content.
    
    Returns:
        str: Formatted timestamp string
    """
    return datetime.datetime.now().strftime(TIMESTAMP_FORMAT)


# =============================================================================
# DATA FETCHING FUNCTIONS
# =============================================================================

def fetch_threat_feed(feed_url: str, feed_name: str) -> Optional[str]:
    """
    Fetch raw data from a threat intelligence feed URL with robust error handling.
    
    This function implements retry logic and comprehensive error handling to ensure
    reliability when working with external data sources, which is critical in
    production threat intelligence systems.
    
    Args:
        feed_url (str): URL of the threat intelligence feed
        feed_name (str): Human-readable name of the feed for logging
        
    Returns:
        Optional[str]: Raw feed data as string, or None if fetch failed
    """
    print(f"[INFO] Fetching {feed_name} from: {feed_url}")
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Configure session with appropriate headers
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'ThreatIntelligenceAggregator/1.0 (+security-research)'
            })
            
            # Make HTTP request with timeout
            response = session.get(feed_url, timeout=HTTP_TIMEOUT)
            
            # Check if request was successful
            response.raise_for_status()
            
            print(f"[SUCCESS] Successfully fetched {feed_name} ({len(response.text)} bytes)")
            return response.text
            
        except requests.exceptions.RequestException as e:
            error_type = type(e).__name__
            print(f"[ERROR] Attempt {attempt}/{MAX_RETRIES} failed for {feed_name}: {error_type} - {str(e)}")
            
            # If this wasn't the last attempt, wait before retrying
            if attempt < MAX_RETRIES:
                print(f"[INFO] Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                print(f"[CRITICAL] All {MAX_RETRIES} attempts failed for {feed_name}")
                return None
                
        except Exception as e:
            print(f"[CRITICAL] Unexpected error fetching {feed_name}: {type(e).__name__} - {str(e)}")
            return None
    
    return None


# =============================================================================
# DATA PARSING FUNCTIONS
# =============================================================================

def parse_feodo_tracker_ips(raw_data: str) -> Set[str]:
    """
    Parse Feodo Tracker CSV data to extract malicious IP addresses.
    
    The Feodo Tracker feed provides C2 botnet IPs in CSV format. This function
    handles the specific format and filters out comments and invalid entries.
    
    Args:
        raw_data (str): Raw CSV data from Feodo Tracker
        
    Returns:
        Set[str]: Set of unique, validated IP addresses
    """
    print("[INFO] Parsing Feodo Tracker IP addresses...")
    
    ip_addresses = set()
    
    try:
        # Use StringIO to treat the string as a file-like object for csv.reader
        csv_data = StringIO(raw_data)
        csv_reader = csv.reader(csv_data)
        
        for row_num, row in enumerate(csv_reader, 1):
            # Skip empty rows or comments (lines starting with #)
            if not row or (row[0].strip().startswith('#')):
                continue
                
            # Extract IP address from first column
            potential_ip = row[0].strip()
            
            # Validate and add IP address
            if validate_ip_address(potential_ip):
                ip_addresses.add(potential_ip)
            else:
                print(f"[WARNING] Invalid IP address on line {row_num}: {potential_ip}")
                
    except Exception as e:
        print(f"[ERROR] Failed to parse Feodo Tracker data: {type(e).__name__} - {str(e)}")
        return set()
    
    print(f"[SUCCESS] Parsed {len(ip_addresses)} unique IP addresses from Feodo Tracker")
    return ip_addresses


def parse_urlhaus_urls(raw_data: str) -> List[Dict[str, str]]:
    """
    Parse URLhaus CSV data to extract malware-associated URLs and threat types.
    
    URLhaus provides detailed information about malware URLs including threat
    classification. This function extracts URLs and their associated threat types.
    
    Args:
        raw_data (str): Raw CSV data from URLhaus
        
    Returns:
        List[Dict[str, str]]: List of dictionaries containing URL and threat type
    """
    print("[INFO] Parsing URLhaus malware URLs...")
    
    malware_urls = []
    
    try:
        csv_data = StringIO(raw_data)
        csv_reader = csv.reader(csv_data)
        
        # Skip header row(s) and comments
        header_found = False
        for row_num, row in enumerate(csv_reader, 1):
            # Skip empty rows or comments
            if not row or row[0].strip().startswith('#'):
                continue
                
            # Look for the header row to understand CSV structure
            if not header_found and 'url' in [col.lower() for col in row]:
                print(f"[INFO] Found URLhaus CSV header at line {row_num}")
                header_found = True
                continue
            
            # Process data rows (URLhaus CSV typically has: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter)
            if len(row) >= 6:  # Ensure we have enough columns
                url = row[2].strip()  # URL is typically in 3rd column (index 2)
                threat_type = row[5].strip() if len(row) > 5 else 'unknown'  # Threat type in 6th column
                
                # Validate URL and add to results
                if validate_url(url):
                    malware_urls.append({
                        'url': url,
                        'threat_type': threat_type if threat_type else 'unknown'
                    })
                else:
                    print(f"[WARNING] Invalid URL on line {row_num}: {url[:50]}...")
                    
    except Exception as e:
        print(f"[ERROR] Failed to parse URLhaus data: {type(e).__name__} - {str(e)}")
        return []
    
    print(f"[SUCCESS] Parsed {len(malware_urls)} malware URLs from URLhaus")
    return malware_urls


# =============================================================================
# DATA CONSOLIDATION FUNCTIONS
# =============================================================================

def consolidate_threat_data(ip_addresses: Set[str], malware_urls: List[Dict[str, str]]) -> Dict:
    """
    Consolidate all parsed threat intelligence data into a unified structure.
    
    This function deduplicates data and organizes it for easy reporting and analysis.
    The consolidation step is crucial in threat intelligence to avoid duplicate
    alerts and provide clean data for downstream security tools.
    
    Args:
        ip_addresses (Set[str]): Set of malicious IP addresses
        malware_urls (List[Dict[str, str]]): List of malware URL dictionaries
        
    Returns:
        Dict: Consolidated threat intelligence data structure
    """
    print("[INFO] Consolidating threat intelligence data...")
    
    # Deduplicate URLs while preserving threat type information
    unique_urls = {}
    for url_data in malware_urls:
        url = url_data['url']
        threat_type = url_data['threat_type']
        
        # If URL already exists, combine threat types
        if url in unique_urls:
            existing_types = set(unique_urls[url]['threat_type'].split(', '))
            existing_types.add(threat_type)
            unique_urls[url]['threat_type'] = ', '.join(sorted(existing_types))
        else:
            unique_urls[url] = url_data.copy()
    
    # Analyze threat type distribution for reporting
    threat_type_stats = Counter()
    for url_data in unique_urls.values():
        for threat in url_data['threat_type'].split(', '):
            threat_type_stats[threat.strip()] += 1
    
    consolidated_data = {
        'metadata': {
            'generation_timestamp': datetime.datetime.now().isoformat(),
            'total_feeds_processed': len(THREAT_FEEDS),
            'feed_sources': list(THREAT_FEEDS.keys())
        },
        'summary': {
            'total_malicious_ips': len(ip_addresses),
            'total_malware_urls': len(unique_urls),
            'total_unique_iocs': len(ip_addresses) + len(unique_urls),
            'threat_type_distribution': dict(threat_type_stats)
        },
        'iocs': {
            'malicious_ips': sorted(list(ip_addresses)),  # Sort for consistent output
            'malware_urls': list(unique_urls.values())
        }
    }
    
    print(f"[SUCCESS] Consolidated data: {consolidated_data['summary']['total_unique_iocs']} unique IOCs")
    return consolidated_data


# =============================================================================
# REPORT GENERATION FUNCTIONS
# =============================================================================

def generate_markdown_report(threat_data: Dict) -> str:
    """
    Generate a comprehensive Markdown threat intelligence report.
    
    This function creates a professional, well-structured report that security
    analysts can easily read and use for threat hunting and incident response.
    
    Args:
        threat_data (Dict): Consolidated threat intelligence data
        
    Returns:
        str: Complete Markdown report as string
    """
    print("[INFO] Generating Markdown threat intelligence report...")
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    metadata = threat_data['metadata']
    summary = threat_data['summary']
    iocs = threat_data['iocs']
    
    # Build the Markdown report
    report_lines = [
        "# Threat Intelligence Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Feeds Processed:** {metadata['total_feeds_processed']}",
        f"**Total IOCs Found:** {summary['total_unique_iocs']}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This automated threat intelligence report aggregates indicators of compromise (IOCs) "
        f"from {metadata['total_feeds_processed']} different threat intelligence feeds. "
        f"A total of **{summary['total_unique_iocs']} unique IOCs** were identified, consisting of:",
        "",
        f"- **{summary['total_malicious_ips']}** malicious IP addresses",
        f"- **{summary['total_malware_urls']}** malware-associated URLs",
        "",
        "### Threat Type Distribution",
        ""
    ]
    
    # Add threat type statistics
    if summary['threat_type_distribution']:
        for threat_type, count in sorted(summary['threat_type_distribution'].items()):
            report_lines.append(f"- **{threat_type}:** {count} instances")
        report_lines.append("")
    
    report_lines.extend([
        "---",
        "",
        "## Malicious C2 IP Addresses",
        "",
        f"The following **{summary['total_malicious_ips']} IP addresses** have been identified "
        "as command and control (C2) infrastructure associated with botnets:",
        ""
    ])
    
    # Add IP addresses table
    if iocs['malicious_ips']:
        report_lines.extend([
            "| IP Address | Status |",
            "|------------|--------|"
        ])
        
        for ip in iocs['malicious_ips']:
            report_lines.append(f"| `{ip}` | Active C2 |")
        
        report_lines.append("")
    else:
        report_lines.append("*No malicious IP addresses found in current feeds.*")
        report_lines.append("")
    
    # Add malware URLs section
    report_lines.extend([
        "---",
        "",
        "## Malware-Associated URLs",
        "",
        f"The following **{summary['total_malware_urls']} URLs** have been identified "
        "as hosting or distributing malware:",
        ""
    ])
    
    if iocs['malware_urls']:
        report_lines.extend([
            "| URL | Threat Type |",
            "|-----|-------------|"
        ])
        
        for url_data in iocs['malware_urls']:
            # Truncate very long URLs for readability
            display_url = url_data['url']
            if len(display_url) > 80:
                display_url = display_url[:77] + "..."
                
            report_lines.append(f"| `{display_url}` | {url_data['threat_type']} |")
        
        report_lines.append("")
    else:
        report_lines.append("*No malware URLs found in current feeds.*")
        report_lines.append("")
    
    # Add data sources and methodology
    report_lines.extend([
        "---",
        "",
        "## Data Sources",
        "",
        "This report aggregates data from the following threat intelligence sources:",
        ""
    ])
    
    for feed_key, feed_config in THREAT_FEEDS.items():
        report_lines.extend([
            f"### {feed_config['name']}",
            f"- **URL:** {feed_config['url']}",
            f"- **Type:** {feed_config['type']}",
            f"- **Description:** {feed_config['description']}",
            ""
        ])
    
    report_lines.extend([
        "---",
        "",
        "## Usage Recommendations",
        "",
        "### For Security Operations Centers (SOCs)",
        "",
        "1. **Network Monitoring:** Block or monitor traffic to/from the listed IP addresses",
        "2. **URL Filtering:** Block access to the identified malware URLs",
        "3. **Threat Hunting:** Search logs for historical connections to these IOCs",
        "4. **Incident Response:** Investigate any systems that have communicated with these IOCs",
        "",
        "### For Threat Intelligence Teams",
        "",
        "1. **IOC Enrichment:** Correlate these IOCs with internal threat data",
        "2. **Attribution:** Research the threat actors behind these IOCs",
        "3. **Trend Analysis:** Monitor changes in IOC patterns over time",
        "",
        "---",
        "",
        f"*Report generated by Threat Intelligence Automation Script v1.0*",
        f"*Generation completed at: {timestamp}*"
    ])
    
    report_content = "\n".join(report_lines)
    print(f"[SUCCESS] Generated Markdown report ({len(report_content)} characters)")
    return report_content


def save_report_to_file(report_content: str, filename: str) -> bool:
    """
    Save the generated threat intelligence report to a file.
    
    Args:
        report_content (str): Complete Markdown report content
        filename (str): Target filename for the report
        
    Returns:
        bool: True if file was saved successfully, False otherwise
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_content)
        print(f"[SUCCESS] Report saved to: {filename}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save report to {filename}: {type(e).__name__} - {str(e)}")
        return False


# =============================================================================
# MAIN EXECUTION FUNCTION
# =============================================================================

def main():
    """
    Main execution function that orchestrates the entire threat intelligence
    aggregation process.
    
    This function coordinates all the individual components: fetching data,
    parsing IOCs, consolidating results, and generating the final report.
    """
    print("=" * 70)
    print("THREAT INTELLIGENCE AUTOMATION SCRIPT")
    print("=" * 70)
    print(f"Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Initialize data collection containers
    all_ip_addresses = set()
    all_malware_urls = []
    successful_feeds = []
    failed_feeds = []
    
    # Process each configured threat intelligence feed
    for feed_key, feed_config in THREAT_FEEDS.items():
        print(f"Processing feed: {feed_config['name']}")
        print("-" * 50)
        
        # Fetch raw data from the feed
        raw_data = fetch_threat_feed(feed_config['url'], feed_config['name'])
        
        if raw_data is None:
            print(f"[ERROR] Skipping {feed_config['name']} due to fetch failure")
            failed_feeds.append(feed_key)
            print()
            continue
        
        # Parse the data based on feed type
        try:
            if feed_config['type'] == 'ip_addresses':
                # Parse IP addresses (Feodo Tracker)
                parsed_ips = parse_feodo_tracker_ips(raw_data)
                all_ip_addresses.update(parsed_ips)
                
            elif feed_config['type'] == 'malware_urls':
                # Parse malware URLs (URLhaus)
                parsed_urls = parse_urlhaus_urls(raw_data)
                all_malware_urls.extend(parsed_urls)
                
            successful_feeds.append(feed_key)
            print(f"[SUCCESS] Successfully processed {feed_config['name']}")
            
        except Exception as e:
            print(f"[ERROR] Failed to process {feed_config['name']}: {type(e).__name__} - {str(e)}")
            failed_feeds.append(feed_key)
        
        print()
    
    # Check if we have any successful feeds
    if not successful_feeds:
        print("[CRITICAL] No threat intelligence feeds were successfully processed!")
        print("Cannot generate report without threat data. Exiting...")
        sys.exit(1)
    
    # Report on feed processing results
    print("FEED PROCESSING SUMMARY")
    print("-" * 30)
    print(f"Successful feeds: {len(successful_feeds)}/{len(THREAT_FEEDS)}")
    if failed_feeds:
        print(f"Failed feeds: {', '.join(failed_feeds)}")
    print()
    
    # Consolidate all collected threat intelligence data
    consolidated_data = consolidate_threat_data(all_ip_addresses, all_malware_urls)
    
    # Generate the Markdown report
    report_content = generate_markdown_report(consolidated_data)
    
    # Save report to file with timestamp
    timestamp = get_current_timestamp()
    report_filename = REPORT_FILENAME_FORMAT.format(timestamp=timestamp)
    
    if save_report_to_file(report_content, report_filename):
        print()
        print("=" * 70)
        print("THREAT INTELLIGENCE AUTOMATION COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print(f"Report File: {report_filename}")
        print(f"Total IOCs: {consolidated_data['summary']['total_unique_iocs']}")
        print(f"Malicious IPs: {consolidated_data['summary']['total_malicious_ips']}")
        print(f"Malware URLs: {consolidated_data['summary']['total_malware_urls']}")
        print(f"Completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("[CRITICAL] Failed to save threat intelligence report!")
        sys.exit(1)


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Script interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[CRITICAL] Unexpected error in main execution: {type(e).__name__} - {str(e)}")
        sys.exit(1)