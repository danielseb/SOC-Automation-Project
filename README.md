# SOC Automation Lab: Building a Complete Security Operations Center Environment

## Project Overview
This project demonstrates my implementation of a complete Security Operations Center (SOC) automation lab environment using open-source security tools. I designed and deployed an end-to-end security monitoring solution that includes SIEM/XDR capabilities, case management, and SOAR functionality to automate security incident response workflows.

![SOC Automation Lab Architecture](https://placeholder-image.com/soc-lab-architecture.png)

## Motivation
As an aspiring SOC Analyst, I wanted to gain hands-on experience with the core technologies used in modern security operations centers. This project allowed me to:
- Create a realistic environment for detecting and responding to security incidents
- Develop automation skills to improve efficiency in security operations
- Gain practical experience with industry-standard security tools
- Demonstrate my technical capabilities to potential employers

## Technologies Used
- **Wazuh** - Open-source SIEM/XDR for event collection, analysis, and alerting
- **TheHive** - Security incident response platform and case management
- **Shuffle** - Security orchestration, automation, and response (SOAR) platform
- **Sysmon** - Enhanced Windows system monitoring for detailed event logging
- **Windows 10** - Client endpoint for generating security telemetry
- **Ubuntu 22.04** - Server platform for hosting security infrastructure
- **VirusTotal** - Threat intelligence integration for malware detection
- **Mimikatz** - Used for simulating credential harvesting attacks

## Architecture & Implementation

### Phase 1: Planning and Infrastructure Design
I began by creating a detailed logical diagram to visualize the SOC automation lab and understand the data flow between different components. This planning phase was crucial for ensuring all systems would communicate properly.

My architecture consisted of:
- Windows 10 client (endpoint generating security events)
- Wazuh Manager server (central log collection and analysis)
- TheHive server (case management system)
- Shuffle (SOAR platform for workflow automation)

### Phase 2: System Deployment
I deployed the infrastructure using both cloud-based and on-premise virtualization:

1. **Windows 10 Client Configuration:**
   - Deployed Windows 10 VM with 4GB RAM and 50GB storage
   - Installed and configured Sysmon with a comprehensive configuration file to capture detailed system events
   - Implemented the Wazuh agent to forward events to the central server

2. **Wazuh Manager Deployment:**
   - Provisioned an Ubuntu 22.04 server with appropriate security hardening
   - Implemented cloud firewall rules to restrict SSH access to my IP only
   - Installed and configured Wazuh manager using the official installation script
   - Configured log archiving for comprehensive event storage and analysis

3. **TheHive Deployment:**
   - Provisioned a separate Ubuntu 22.04 server
   - Installed and configured prerequisite components (Java, Cassandra, Elasticsearch)
   - Deployed TheHive application with proper configurations for external access
   - Created service accounts and API keys for integration with other systems

### Phase 3: Security Monitoring Configuration
I implemented comprehensive monitoring capabilities focused on real-world threat detection:

1. **Advanced Telemetry Collection:**
   - Configured Sysmon for detailed process creation, network connections, and file operations monitoring
   - Modified Wazuh agent configuration to specifically target critical security events
   - Implemented full log ingestion and archiving for comprehensive security analysis

2. **Custom Detection Rules:**
   - Developed a custom Wazuh rule to detect Mimikatz (credential theft tool) based on original filename
   - Implemented detection logic that works even when attackers attempt to evade detection by renaming the executable
   - Mapped detection to relevant MITRE ATT&CK techniques (T1003 - Credential Dumping)

3. **Alert Validation:**
   - Generated test security events using common attack tools
   - Verified proper alert generation and notification
   - Fine-tuned detection rules to eliminate false positives

### Phase 4: Automation and Orchestration
I implemented an end-to-end security automation workflow using Shuffle:

1. **Tool Integration:**
   - Connected Wazuh to Shuffle via webhook integration for real-time alert processing
   - Integrated TheHive using API keys for automated case creation
   - Implemented email notifications for alerting security analysts

2. **Automated Workflow:**
   - Created a complete workflow that triggers on Mimikatz detection
   - Used RegEx to extract the file hash from security alerts
   - Integrated with VirusTotal API for automated threat intelligence enrichment
   - Automatically created cases in TheHive with detailed information
   - Generated email notifications with critical alert details for analyst review

3. **Response Actions:**
   - Implemented automated response capabilities via Wazuh-Shuffle integration
   - Created workflows for common remediation tasks to accelerate incident response

## Challenges & Solutions
Throughout this project, I encountered and overcame several significant challenges:

1. **Integration Issues:**
   - **Challenge:** Initial connection issues between Shuffle and TheHive due to API compatibility
   - **Solution:** Forked the VirusTotal app in Shuffle to modify the API endpoint from /report to /ID, resolving a 404 error

2. **Performance Optimization:**
   - **Challenge:** Resource constraints on TheHive server causing elasticsearch service failures
   - **Solution:** Modified JVM options to limit Java memory allocation, bringing stability to the environment

3. **Security Hardening:**
   - **Challenge:** Balancing security with functionality for cloud-hosted components
   - **Solution:** Implemented temporary, targeted firewall rules during integration testing, followed by immediate restriction after validation

## Results & Learnings
This project resulted in a fully functional SOC automation environment capable of:
- Detecting advanced attack techniques in real-time
- Enriching alerts with threat intelligence
- Creating cases automatically in TheHive
- Notifying security analysts via email
- Streamlining the incident response process

Key learnings included:
- The importance of detailed planning before implementation
- How to integrate multiple security tools to create automated workflows
- Practical application of the MITRE ATT&CK framework for threat detection
- Techniques for simulating and detecting common attack vectors

## Future Improvements
I plan to enhance this project with:
- Integration with additional threat intelligence platforms
- Implementation of machine learning-based anomaly detection
- Expansion to include network traffic analysis (Suricata/Zeek)
- Development of a security metrics dashboard
- Additional automated response actions for common security incidents

## Conclusion
This SOC Automation Lab project demonstrates my practical skills in security monitoring, detection, and response automation. By building this environment from scratch, I've gained valuable hands-on experience with the tools and techniques used by SOC Analysts in real-world security operations centers. This project reflects my commitment to continuous learning and my readiness to contribute effectively as a SOC Analyst.

## References
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [TheHive Project](https://thehive-project.org/)
- [Shuffle Documentation](https://shuffler.io/docs)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
