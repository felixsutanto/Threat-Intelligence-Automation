# Threat Intelligence Automation

A professional-grade Python script that automatically aggregates, parses, and reports on Indicators of Compromise (IOCs) from multiple public threat intelligence feeds. This tool demonstrates practical DevSecOps automation capabilities for cybersecurity professionals.

## 🎯 Project Overview

This project showcases the automation of threat intelligence collection and reporting, a critical capability in modern Security Operations Centers (SOCs). The script fetches real-time threat data from multiple sources, processes it for actionable intelligence, and generates professional reports for security analysts.

### Key Features

- **Multi-Feed Aggregation**: Automatically fetches data from multiple threat intelligence sources
- **IOC Parsing & Validation**: Extracts and validates malicious IPs and URLs with robust error handling
- **Data Deduplication**: Eliminates duplicate indicators while preserving threat classification
- **Professional Reporting**: Generates detailed Markdown reports with executive summaries
- **Production-Ready Code**: Implements retry logic, comprehensive logging, and error recovery
- **Modular Architecture**: Clean, maintainable code structure suitable for enterprise environments

## 🔍 Threat Intelligence Sources

The script currently integrates with these public threat feeds:

1. **Feodo Tracker (Abuse.ch)**
   - **Data**: C2 Botnet IP Addresses
   - **Format**: CSV
   - **Update Frequency**: Real-time
   - **Use Case**: Network monitoring and blocking

2. **URLhaus (Abuse.ch)**
   - **Data**: Recent Malware-Associated URLs
   - **Format**: CSV with threat classification
   - **Update Frequency**: Continuous
   - **Use Case**: Web filtering and threat hunting

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Internet connection for accessing threat feeds
- Write permissions in the current directory (for report generation)

### Installation

1. **Clone or download the project files:**
   ```bash
   # Download the three main files:
   # - threat_aggregator.py
   # - requirements.txt
   # - README.md
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the script:**
   ```bash
   python threat_aggregator.py
   ```

### Expected Output

The script will:
1. Display real-time progress as it fetches and processes each feed
2. Show summary statistics of IOCs discovered
3. Generate a timestamped Markdown report (e.g., `threat_report_2024-01-15_143022.md`)

## 📊 Sample Report Structure

The generated reports include:

```markdown
# Threat Intelligence Report

**Generated:** 2024-01-15 14:30:22 UTC
**Feeds Processed:** 2
**Total IOCs Found:** 1,247

## Executive Summary
- 892 malicious IP addresses
- 355 malware-associated URLs

## Malicious C2 IP Addresses
| IP Address | Status |
|------------|--------|
| 192.0.2.1  | Active C2 |

## Malware-Associated URLs
| URL | Threat Type |
|-----|-------------|
| hxxp://malware.example[.]com | malware_download |
```

## 🏗️ Architecture & Design

### Code Structure

```
threat_aggregator.py
├── Configuration Section      # Feed URLs and settings
├── Utility Functions         # IP/URL validation helpers
├── Data Fetching Functions   # HTTP requests with retry logic
├── Data Parsing Functions    # Feed-specific parsers
├── Data Consolidation       # Deduplication and merging
├── Report Generation        # Markdown report creation
└── Main Execution          # Orchestration logic
```

### Key Design Principles

- **Separation of Concerns**: Each function has a single, well-defined responsibility
- **Error Resilience**: Comprehensive error handling and recovery mechanisms
- **Configurability**: Easy to modify feed sources without changing core logic
- **Extensibility**: Simple to add new threat intelligence feeds
- **Maintainability**: Heavily commented code with clear documentation

## 🔧 Customization

### Adding New Threat Feeds

To add a new threat intelligence source, modify the `THREAT_FEEDS` configuration:

```python
THREAT_FEEDS = {
    'your_new_feed': {
        'name': 'Your Threat Feed Name',
        'url': 'https://example.com/threat-feed.csv',
        'type': 'ip_addresses',  # or 'malware_urls'
        'description': 'Description of the feed'
    }
}
```

Then implement a corresponding parser function following the existing patterns.

### Configuration Options

Key settings can be modified at the top of the script:

- `HTTP_TIMEOUT`: Request timeout in seconds (default: 30)
- `MAX_RETRIES`: Number of retry attempts for failed requests (default: 3)
- `RETRY_DELAY`: Delay between retry attempts (default: 2 seconds)

## 🧪 Testing & Validation

### Manual Testing

1. **Network Connectivity Test**:
   ```bash
   curl -I https://feodotracker.abuse.ch/downloads/ipblocklist.csv
   ```

2. **Python Environment Test**:
   ```bash
   python -c "import requests, csv, datetime; print('Dependencies OK')"
   ```

3. **Script Execution Test**:
   ```bash
   python threat_aggregator.py
   ```

### Expected Behavior

- **Success Case**: Script completes with generated report file
- **Network Issues**: Script retries failed requests and continues with available data
- **Partial Failures**: Script processes successful feeds and notes failures in output
- **Complete Failure**: Script exits gracefully with error message

## 🛡️ Security Considerations

- **No Credential Storage**: Script uses only public, unauthenticated feeds
- **Safe URL Handling**: URLs are validated and sanitized before processing
- **Timeout Protection**: HTTP requests include timeouts to prevent hanging
- **Error Isolation**: Feed failures don't crash the entire script

## 📈 Professional Use Cases

This script demonstrates several key DevSecOps capabilities:

1. **Automation**: Eliminates manual threat intelligence collection
2. **Integration**: Can be integrated into SIEM/SOAR platforms
3. **Monitoring**: Suitable for scheduled execution (cron jobs)
4. **Reporting**: Generates analyst-ready documentation
5. **Scalability**: Architecture supports adding multiple feeds

## 🚦 Troubleshooting

### Common Issues

**"Connection timeout" errors:**
- Check internet connectivity
- Verify threat feed URLs are accessible
- Increase `HTTP_TIMEOUT` if needed

**"No IOCs found" in report:**
- Verify threat feeds are returning data
- Check if feed formats have changed
- Review parser functions for the specific feeds

**Permission errors:**
- Ensure write permissions in current directory
- Check if antivirus is blocking script execution

## 🤝 Contributing

This project serves as a portfolio demonstration, but improvements are welcome:

1. Additional threat intelligence sources
2. Enhanced parsing capabilities
3. Alternative output formats (JSON, XML)
4. Performance optimizations
5. Unit test coverage

## 📝 License

This project is created for educational and portfolio purposes. The threat intelligence feeds used are publicly available and provided by their respective organizations (Abuse.ch). Please respect the terms of service of each threat intelligence provider.

## 🔮 Future Enhancements

Potential improvements for advanced users:

### Technical Enhancements
- [ ] **Database Integration**: Store IOCs in SQLite/PostgreSQL for historical analysis
- [ ] **API Development**: REST API endpoints for programmatic access
- [ ] **Concurrent Processing**: Parallel feed fetching for improved performance
- [ ] **Caching Layer**: Redis integration for reducing redundant API calls
- [ ] **Configuration Files**: YAML/JSON config files instead of hardcoded settings

### Intelligence Enhancements
- [ ] **IOC Enrichment**: Integrate with VirusTotal, Shodan, or other enrichment APIs
- [ ] **Geolocation Data**: Add geographical information for IP addresses
- [ ] **Threat Attribution**: Link IOCs to known threat actor groups
- [ ] **Confidence Scoring**: Implement reliability scores for different sources
- [ ] **False Positive Detection**: Machine learning for IOC quality assessment

### Operational Enhancements
- [ ] **Alerting Integration**: Slack, email, or webhook notifications
- [ ] **SIEM Integration**: Direct integration with Splunk, ELK, or QRadar
- [ ] **Scheduling**: Built-in cron-like scheduling capabilities
- [ ] **Health Monitoring**: System health checks and uptime monitoring
- [ ] **Multi-format Output**: JSON, XML, STIX/TAXII format support

## 📚 Additional Resources

To deepen your understanding of threat intelligence:

### Recommended Reading
- **"Threat Intelligence: Planning and Direction"** - Understanding TI lifecycle
- **NIST Cybersecurity Framework** - Context for threat intelligence in security programs
- **MITRE ATT&CK Framework** - Threat actor tactics, techniques, and procedures

### Related Technologies
- **STIX/TAXII**: Structured threat information exchange standards
- **YARA Rules**: Pattern matching for malware detection
- **Sigma Rules**: Generic signature format for SIEM systems
- **OpenIOC**: Framework for sharing threat intelligence

### Professional Development
- **SANS FOR578**: Cyber Threat Intelligence course
- **Certified Threat Intelligence Analyst (CTIA)** - Professional certification
- **ISAC Communities**: Industry-specific threat sharing organizations

---