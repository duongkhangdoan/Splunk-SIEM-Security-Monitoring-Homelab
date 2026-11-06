## Overview

A hands-on cybersecurity homelab designed to practice Security Operations Center (SOC) workflows across Windows, Linux, and network environments. The project uses **Splunk Enterprise** as a centralized SIEM to collect security logs, investigate authentication activity, develop detection searches, and automate alerts. **pfSense** provides a network-security monitoring component.

## Lab Architecture

| Component | Role |
|---|---|
| Splunk Enterprise on Ubuntu | Centralized log ingestion, searching, dashboards, and alerting |
| Splunk Universal Forwarder | Sends endpoint logs to Splunk |
| Windows Server (DC1) | Active Directory and Windows security events |
| Windows 10 (WIN10-VM1) | Endpoint authentication events |
| pfSense | Firewall and network traffic logs |
| Linux host | Linux authentication and SSH security events |
| VirtualBox | Virtualized lab environment |

**Log flow:** Windows endpoints / Linux / pfSense → log forwarding → Splunk SIEM → SPL searches → dashboards and alerts → SOC investigation.

## Labs

### Lab 1 — Windows Security Monitoring & Brute-Force Detection

- Configure Splunk Enterprise and Windows Universal Forwarders.
- Ingest Windows Security event logs into the `soc_windows` index.
- Analyze successful and failed authentication events, including Event IDs **4624**, **4625**, **4771**, and **4776**.
- Write SPL queries to identify repeated failed logins by account and host.
- Configure a scheduled alert for **five or more failed logins within five minutes**.
- Investigate triggered alerts and compare failed-login events with subsequent successful logins.

### Lab 2 — Splunk Security Dashboards

- Build dashboards for successful and failed login activity.
- Visualize authentication trends, top accounts with failed logins, and event distributions.
- Use SPL searches and dashboard panels to support security triage.

### Lab 3 — Network Traffic Monitoring with pfSense

- Configure pfSense firewall logging and forward relevant events to Splunk.
- Review allowed and blocked traffic, source and destination addresses, and ports.
- Investigate suspicious connections and develop network-focused SPL searches.

### Lab 4 — Linux Security Log Monitoring

- Collect Linux authentication and SSH logs in Splunk.
- Analyze successful and failed SSH authentication attempts.
- Create detection searches and alerts for repeated authentication failures.

## Tools & Technologies

| Area | Tools / Concepts |
|---|---|
| SIEM & detection | Splunk Enterprise, SPL, scheduled alerts, dashboards |
| Endpoint logging | Windows Security Event Logs, Splunk Universal Forwarder |
| Network monitoring | pfSense, firewall logs, IP addresses and ports |
| Linux monitoring | Ubuntu, authentication logs, SSH |
| Infrastructure | Windows Server, Active Directory, Windows 10, VirtualBox |
| SOC workflows | Event correlation, alert triage, incident investigation |

## Skills Demonstrated

- Centralized security log collection and SIEM configuration
- Windows and Linux authentication log analysis
- SPL search development and automated detection rules
- Brute-force detection and alert investigation
- Security dashboard development and visualization
- Firewall log analysis and network security monitoring
- Evidence-based SOC triage and incident documentation

## Example Windows Detection Search

The following search identifies accounts with at least five failed login events during the last five minutes:

```spl
index=soc_windows host="WIN10-VM1" EventCode=4625 earliest=-5m
| eval username=mvindex(Account_Name,-1)
| stats count as failed_attempts by host username
| where failed_attempts >= 5
```

> **Lab note:** The `Account_Name` extraction above matches the field structure observed in this homelab. Other Windows log formats may require a different field extraction. Repeated failed logins indicate suspicious activity but do not, by themselves, prove malicious access.

## Learning Outcomes

This project develops practical experience in security monitoring, log investigation, threat detection, and incident triage. It is relevant to entry-level **SOC Analyst**, **Cybersecurity Analyst**, and **Security Operations Internship** roles.
