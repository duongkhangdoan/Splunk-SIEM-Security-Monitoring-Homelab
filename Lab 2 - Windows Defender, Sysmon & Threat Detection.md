## Overview

This lab implements endpoint security monitoring in a Windows Active Directory environment using **Microsoft Defender Antivirus**, **Sysmon**, **Splunk Universal Forwarder**, and **Splunk Enterprise**. It demonstrates process monitoring, detection of encoded PowerShell execution, antivirus event collection, and automated SIEM alerting.

The lab uses a Windows 10 domain-joined endpoint (`WIN10-VM1`) in the `ad.lab` domain and the existing Splunk index `soc_windows`. All tests were conducted in an isolated virtual lab with harmless commands and the standard EICAR antivirus test file.

## Objectives

- Enable and validate Microsoft Defender protection.
- Install Sysmon and monitor process creation.
- Forward Windows and Sysmon logs to Splunk.
- Detect PowerShell execution using `-EncodedCommand`.
- Create and validate scheduled security alerts.
- Test Microsoft Defender with EICAR and investigate detection/remediation events.

## Lab Environment

| Component | Purpose |
| --- | --- |
| Windows 10 Enterprise (`WIN10-VM1`) | Domain-joined monitored endpoint |
| Windows Server (`DC1`) | Active Directory domain controller / domain policy administration |
| Microsoft Defender Antivirus | Endpoint antivirus detection and remediation |
| Sysmon64 | Detailed process creation telemetry |
| Splunk Universal Forwarder | Windows Event Log forwarding |
| Splunk Enterprise | Centralized search, detection, and alerting |
| Splunk index: `soc_windows` | Centralized Windows event storage |

## Part 1 – Enable Microsoft Defender and Install Sysmon

### 1. Validate Microsoft Defender

A domain Group Policy named `Disable Protections` previously disabled Defender and firewall settings. The domain policy was reviewed and adjusted so that the lab endpoint could use Defender without affecting the remaining security monitoring workflow. Policy application was checked with:

```powershell
gpresult /r /scope computer
```

Defender service and protection status were verified:

```powershell
Get-Service WinDefend
Get-MpComputerStatus | Format-List AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled
```

Expected results: `WinDefend` is **Running** and all four protection fields are `True`.  

<img width="758" height="114" alt="image" src="https://github.com/user-attachments/assets/d8d93994-14e6-4d01-b576-a0e1490fa88d" />  
<img width="613" height="983" alt="image" src="https://github.com/user-attachments/assets/9104177b-4a4c-42e3-92bb-ecb5c69231c4" />


### 2. Install and verify Sysmon

Sysmon binaries were placed in `C:\Sysmon`. Sysmon64 was installed as a Windows service and verified:

```powershell
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i
Get-Service Sysmon64
```

<img width="546" height="257" alt="image" src="https://github.com/user-attachments/assets/fa13f7f8-c279-4a5e-b847-a3ea847c38ec" />

> If Sysmon is already installed, verify the existing service rather than installing it again. Sysmon configurations should be reviewed and tuned for production use.

Open **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational** and confirm that events are recorded. **Event ID 1** represents process creation.

<img width="797" height="503" alt="image" src="https://github.com/user-attachments/assets/84fcf2d1-701e-4f68-a445-b053f528a202" />

### 3. Validate process creation telemetry

Launch Notepad from PowerShell:

```powershell
notepad.exe
```

Review the resulting Sysmon Event ID 1, including:

- `Image`: executable path of the new process.
- `CommandLine`: arguments used to launch the process.
- `ParentImage`: executable that launched the process.
- `User`: security context of the process.

For this test, `Image` identified `notepad.exe`, and `ParentImage` identified `powershell.exe`.

## Part 2 – Forward Endpoint Logs to Splunk

### 4. Configure Splunk Universal Forwarder

On `WIN10-VM1`, edit:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

Use the following log inputs:

```ini
[WinEventLog://Security]
disabled = 0
index = soc_windows

[WinEventLog://System]
disabled = 0
index = soc_windows

[WinEventLog://Application]
disabled = 0
index = soc_windows

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = soc_windows

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = soc_windows
renderXml = 1
```

<img width="615" height="606" alt="image" src="https://github.com/user-attachments/assets/5ee0baeb-bb62-49eb-be3a-e3d870fa7ddc" />

The existing forwarder output was already configured to send events to Splunk Enterprise. Restart and verify the forwarder:

```powershell
Restart-Service SplunkForwarder
Get-Service SplunkForwarder
```

### 5. Verify ingestion

In Splunk Search & Reporting, run:

```spl
index=soc_windows host="WIN10-VM1"
| stats count by host source
| sort - count
```

<img width="975" height="225" alt="image" src="https://github.com/user-attachments/assets/3af048eb-4e24-44a4-a52a-c6841051aba3" />

Confirm that Security, System, Application, Sysmon Operational, and Windows Defender Operational sources are present. The lab successfully ingested all five sources.

## Part 3 – Detect Suspicious PowerShell Execution

### 6. Generate a harmless encoded PowerShell command

On `WIN10-VM1`, open PowerShell and run:

```powershell
$command = 'Write-Output 123'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -NoProfile -EncodedCommand $encoded
```

The command prints `123`. The `-EncodedCommand` parameter passes a Base64-encoded UTF-16LE command to PowerShell. Encoding alone does **not** mean a command is malicious, but it can be useful detection context.

### 7. Search Sysmon process creation events

Search the Sysmon source and Event ID 1 in Splunk:

```spl
index=soc_windows host="WIN10-VM1" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "EncodedCommand" "<EventID>1</EventID>"
```

<img width="975" height="322" alt="image" src="https://github.com/user-attachments/assets/e89b93c3-0d76-454e-96d0-a6c10e35f7e6" />

Review the matching XML event for `Image`, `CommandLine`, `ParentImage`, and `User`. The observed event showed a PowerShell process launched by PowerShell with `-EncodedCommand` in its command line.

### 8. Create the PowerShell detection alert

Choose **Save As → Alert** and configure:

| Setting | Value |
| --- | --- |
| Title | `Suspiciou Powershell Encoded` (lab alert name) |
| Alert type | Scheduled |
| Cron expression | `*/5 * * * *` |
| Search time range | Last 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger | Once |
| Severity | Medium |
| Trigger action | Add to Triggered Alerts |

<img width="704" height="882" alt="image" src="https://github.com/user-attachments/assets/85de0fb0-8acb-48e8-86a9-05b3934bb629" />

Execute the harmless encoded PowerShell command again and review **Activity → Triggered Alerts**. The scheduled alert triggered at **2:45 PM EST on November 6, 2026**. **View Results** confirmed a matching Sysmon Event ID 1 containing `-EncodedCommand`.

<img width="975" height="71" alt="image" src="https://github.com/user-attachments/assets/4c8fdc88-42cd-462b-9086-aff6d00c3bd8" />

## Part 4 – Microsoft Defender Antivirus Detection

### 9. Validate Defender Operational logging

Check the Defender event channel:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Windows Defender/Operational" |
    Format-List LogName, IsEnabled, RecordCount
```

The channel was enabled and its events were forwarded to the `soc_windows` index through the configuration above.

### 10. Perform the EICAR antivirus test

Using Edge on `WIN10-VM1`, download the standard `eicar.com.txt` test file from the official EICAR website:

https://www.eicar.org/download-anti-malware-testfile/

EICAR is an industry-standard **non-malicious antivirus test file**. Keep real-time protection enabled. Do not run malware or disable security controls.

Microsoft Defender displayed **Threat blocked** and recorded the test file in Protection History. Verify the detection with:

```powershell
Get-MpThreatDetection |
    Select-Object InitialDetectionTime, ThreatID, ActionSuccess, Resources
```

<img width="747" height="328" alt="image" src="https://github.com/user-attachments/assets/b34cce0c-c9bd-44a7-979b-1d78aae2f21c" />

Observed results included:

- Threat ID: `2147519003`
- Test file: `C:\Users\loan.duong\Downloads\eicar.com.txt`
- `ActionSuccess`: `True`
  
<img width="863" height="112" alt="image" src="https://github.com/user-attachments/assets/b1fe97af-70c6-4770-89a2-d41febdbabc6" />

### 11. Investigate Defender detection and remediation events

Search Defender Operational logs in Splunk:

```spl
index=soc_windows host="WIN10-VM1" source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" ("<EventID>1116</EventID>" OR "<EventID>1117</EventID>")
```

<img width="901" height="482" alt="image" src="https://github.com/user-attachments/assets/e071e734-31c6-49bc-acc5-8f0a76b4aa60" />

The lab returned both events:

| Event ID | Meaning | Observed result |
| --- | --- | --- |
| 1116 | Malware or threat detected | EICAR test file detected |
| 1117 | Remediation action performed | Successful quarantine action |

The XML records identified `Virus:DOS/EICAR_Test_File`, severity `Severe`, and the affected file path.

### 12. Create the Defender malware detection alert

Use a search focused on detection events:

```spl
index=soc_windows host="WIN10-VM1" source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" "<EventID>1116</EventID>"
```

Save as an alert with the following configuration:

| Setting | Value |
| --- | --- |
| Title | `Windows Defender Malware Detection` |
| Alert type | Scheduled |
| Cron expression | `*/5 * * * *` |
| Search time range | Last 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger | Once |
| Severity | High |
| Trigger action | Add to Triggered Alerts |  

<img width="951" height="232" alt="image" src="https://github.com/user-attachments/assets/37f81225-ddef-4f50-85d3-bf1876a327c2" />

Repeat the harmless EICAR test to generate a new Defender detection. The scheduled malware alert triggered at **3:25:01 PM EST on November 6, 2026**.

<img width="949" height="197" alt="image" src="https://github.com/user-attachments/assets/85b1aba5-e3bc-4e68-8d90-cb4a2a3f0156" />

## Final Validation

| Detection | Evidence | Result |
| --- | --- | --- |
| Sysmon process monitoring | Event ID 1 and process details visible in Splunk | Passed |
| Encoded PowerShell detection | Scheduled alert triggered at 2:45 PM EST | Passed |
| Defender antivirus test | EICAR detected and successfully handled | Passed |
| Defender log forwarding | Event IDs 1116 and 1117 visible in Splunk | Passed |
| Automated malware detection | Scheduled alert triggered at 3:25:01 PM EST | Passed |

## What I Learned

1. **Endpoint telemetry:** How Sysmon captures process creation and how parent-child process relationships help explain execution behavior.
2. **Windows security controls:** How domain Group Policy affects Defender configuration and how to verify protection and Windows services.
3. **Centralized log collection:** How to configure Splunk Universal Forwarder to ingest multiple Windows event channels into a shared index.
4. **SIEM investigation:** How to use Splunk SPL to filter by host, source, event ID, and command-line indicators, then inspect raw XML event details.
5. **Behavior-based detection:** Why encoded PowerShell execution can warrant investigation without being inherently malicious.
6. **Antivirus event analysis:** How Defender Event ID 1116 records detections and Event ID 1117 records remediation actions.
7. **Automated alerting:** How scheduled searches, cron expressions, time windows, severity, and trigger actions turn searches into repeatable security detections.
8. **Detection validation:** How to generate safe test activity, verify the underlying events, and confirm that alerts fire as expected.

## Operational Considerations

This lab used a five-minute schedule and a five-minute search window for simplicity. In production, ingestion delays can cause events to be missed at window boundaries. Use appropriate scheduling offsets, ingestion-lag monitoring, deduplication or throttling, and carefully tuned detection logic. A match on `-EncodedCommand` is an investigation signal, not proof of compromise. The test alerts were scoped to `WIN10-VM1`; production detections would normally cover relevant endpoints more broadly.

## Outcome

**Lab 2 completed:** Sysmon and Microsoft Defender telemetry were centralized in Splunk, and two scheduled security alerts were successfully tested: suspicious encoded PowerShell execution and antivirus malware detection. The lab strengthened practical skills in endpoint security monitoring, event analysis, SPL detection engineering, and SOC alert validation.
