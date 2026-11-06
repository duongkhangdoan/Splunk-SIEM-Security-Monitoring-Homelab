# Lab 1 — Step-by-Step Implementation

## Goal
Collect Windows Security logs from `DC1` and `WIN10-VM1` in Splunk, detect repeated failed logons, and investigate alerts. This document presents the completed workflow in a clean sequence without troubleshooting history.

## 1. Lab Topology and Prerequisites

| Component | Role | Lab value |
|---|---|---|
| Ubuntu | Splunk Enterprise / receiving indexer | `10.10.10.12` |
| Windows Server | Active Directory domain controller | `DC1` |
| Windows 10 | Domain-joined endpoint | `WIN10-VM1` |
| Splunk index | Windows security event storage | `soc_windows` |
| Forwarding port | Universal Forwarder → Splunk | TCP `9997` |

Prerequisites: machines can reach the Ubuntu Splunk host; Splunk Enterprise is installed and accessible through its web interface; Windows Security auditing is enabled for the relevant logon events. The following instructions assume administrator access to the lab machines.

<img width="652" height="178" alt="image" src="https://github.com/user-attachments/assets/c56cb93d-4f0b-4392-9d89-ddc514df8e16" />
<img width="1033" height="199" alt="image" src="https://github.com/user-attachments/assets/4f80822c-a053-47a6-9e8e-0e5b77550b40" />

## 2. Configure Splunk Enterprise on Ubuntu

1. Open Splunk Web (`http://localhost:8000` when browsing on the Ubuntu Splunk machine).
2. Under **Settings → Indexes**, create an index named `soc_windows` if it does not already exist.
3. Open **Settings → Forwarding and receiving → Configure receiving → New Receiving Port**.
4. Enter `9997` and enable the receiver.
5. Confirm that TCP `9997` is reachable from the Windows VMs and allowed through applicable host/network firewalls.

The index is created once on Splunk, **not separately on each Windows endpoint**.  

<img width="975" height="173" alt="image" src="https://github.com/user-attachments/assets/c0d3e360-4bc1-44b9-b4e2-f9b25068aba1" />

## 3. Install Splunk Universal Forwarder on Windows

Perform these steps on **both `DC1` and `WIN10-VM1`**.

1. Install Splunk Universal Forwarder for Windows.
2. Create the forwarder's local administration credentials when prompted. These are **not** required to match a Windows domain account or Splunk Enterprise Web account.
3. If you are not using a Splunk Deployment Server, leave the optional **Deployment Server** fields blank.
4. For **Receiving Indexer**, enter the Ubuntu Splunk address `10.10.10.12` and port `9997`.
5. Complete installation and confirm that the `SplunkForwarder` Windows service is running.

Example PowerShell check (run as administrator):

```powershell
Get-Service SplunkForwarder
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
    Select-Object Name, State, StartName
```

## 4. Configure Security Log Collection

On each Windows machine, create or edit:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
disabled = 0
index = soc_windows
```

<img width="403" height="232" alt="image" src="https://github.com/user-attachments/assets/96646d10-0725-461c-82d9-a75d4d7007e3" />

Confirm that the forwarder destination is configured in:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

Example configuration:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 10.10.10.12:9997
```

<img width="435" height="270" alt="image" src="https://github.com/user-attachments/assets/7edf604e-803a-400c-8b6b-4b29e0f8d4b5" />

If the installer already created the correct output configuration, do not duplicate it.

**Important:** In Windows File Explorer, enable file-name extensions and save `inputs.conf` as a real `.conf` file, not `inputs.conf.txt`.

## 5. Allow the Forwarder to Read Security Logs

The lab's forwarder service ran under `NT SERVICE\SplunkForwarder`. On each Windows machine using this service identity, open **PowerShell as Administrator** and grant read access via the local Event Log Readers group:

```powershell
Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SplunkForwarder"
Get-LocalGroupMember -Group "Event Log Readers"
```

<img width="990" height="171" alt="image" src="https://github.com/user-attachments/assets/ca7694e5-49a6-4bed-90aa-c502b4b595af" />

This permission enables the service identity to read the Security event log under the lab configuration. In managed environments, follow the organization's least-privilege policy and verify the service account and applicable log access policy.

Restart the forwarder service so it picks up the configuration and group membership:

```powershell
Restart-Service SplunkForwarder
Get-Service SplunkForwarder
```

<img width="576" height="119" alt="image" src="https://github.com/user-attachments/assets/05f079e1-243f-4a27-9db3-c370710053ce" />

## 6. Verify Log Forwarding in Splunk

Open **Search & Reporting** and choose **All time** for initial verification.

```spl
index=soc_windows
| stats count by host
| sort - count
```

Expected host names include `DC1` and `WIN10-VM1` (host naming depends on forwarder settings).

Inspect Windows event types:

```spl
index=soc_windows
| stats count by host EventCode
| sort host - count
```

Useful Windows authentication events:

| Event ID | Meaning |
|---|---|
| `4624` | Successful logon |
| `4625` | Failed logon |
| `4771` | Kerberos pre-authentication failed (typically logged on the domain controller) |
| `4776` | NTLM credential validation (success or failure depends on error code) |

## 7. Investigate Failed Logons

Generate failed sign-in attempts using an **authorized test account** on `WIN10-VM1`. The Security log records Event `4625` for the observed failures.

```spl
index=soc_windows host="WIN10-VM1" EventCode=4625
| table _time host EventCode Account_Name Logon_Type Source_Network_Address
| sort - _time
```

In this lab, `Account_Name` was multivalue, with the target username appearing last. Extract and count the target usernames:

```spl
index=soc_windows host="WIN10-VM1" EventCode=4625
| eval username=mvindex(Account_Name,-1)
| stats count as failed_attempts by username
| sort - failed_attempts
```

<img width="975" height="220" alt="image" src="https://github.com/user-attachments/assets/abb36fb4-3d34-47e7-afbd-426060015aa1" />

> Field extraction is source-dependent. Validate the target username from the raw event before reusing this SPL against different Windows event formats.

## 8. Detect Five Failures in a Five-Minute Bucket

For historical analysis, use fixed 5-minute buckets:

```spl
index=soc_windows host="WIN10-VM1" EventCode=4625
| eval username=mvindex(Account_Name,-1)
| bin _time span=5m
| stats count as failed_attempts by _time username
| where failed_attempts >= 5
| sort - _time
```

<img width="975" height="160" alt="image" src="https://github.com/user-attachments/assets/06147219-da73-4033-a1e1-6d3d50949230" />

This search identifies **fixed 5-minute buckets** with at least five failures. It differs from a rolling last-5-minutes alert and can miss activity that straddles a bucket boundary.

## 9. Create the Scheduled Brute-Force Alert

For scheduled monitoring, use this SPL **without** the fixed-time `bin` command:

```spl
index=soc_windows host="WIN10-VM1" EventCode=4625
| eval username=mvindex(Account_Name,-1)
| stats count as failed_attempts by host username
| where failed_attempts >= 5
```


1. In Splunk **Search & Reporting**, run the query with the time range set to **Last 5 minutes**.
2. Select **Save As → Alert**.
3. Enter the following settings:

| Setting | Value |
|---|---|
| Title | `SOC - Brute Force Detection` |
| Description | `Detects 5 or more failed login attempts within 5 minutes` |
| Alert type | Scheduled |
| Schedule | Run on Cron Schedule |
| Cron expression | `* * * * *` |
| Search time range | Last 5 minutes (`earliest=-5m`, `latest=now`) |
| Trigger condition | Number of Results is greater than `0` |
| Trigger | For each result |
| Trigger action | Add to Triggered Alerts |
| Severity | Medium |
| Expires | 24 hours |

4. Save the alert.

**Behavior:** Splunk checks the most recent five minutes of events every minute. A qualifying set of failures can therefore generate repeated alerts until it falls outside the search window. Throttling can be added later to reduce duplicate notifications.

## 10. Validate the Alert

1. On `WIN10-VM1`, simulate at least five failed sign-ins to the lab account `loan.duong` within five minutes.
2. Allow time for the Universal Forwarder to send the logs and for the scheduled search to execute.
3. In Splunk, open **Activity → Triggered Alerts**.
4. Locate **SOC - Brute Force Detection**, then select **View Results**.
5. Confirm the target username and `failed_attempts` count meet the threshold.

The lab produced triggered alerts and showed the test account exceeding the configured threshold.  

<img width="975" height="168" alt="image" src="https://github.com/user-attachments/assets/b80c64f8-c2be-483d-a621-921d550ecadc" />


## 11. Correlate Failed and Successful Logons

After the authorized failed-logon test, perform a successful sign-in to `WIN10-VM1` and search for Events `4625` and `4624`:

```spl
index=soc_windows host="WIN10-VM1" (EventCode=4625 OR EventCode=4624)
| eval username=mvindex(Account_Name,-1)
| search username="loan.duong"
| eval result=case(EventCode=4625,"FAILED",EventCode=4624,"SUCCESS")
| table _time host username EventCode result Logon_Type Source_Network_Address
| sort - _time
```
  
The observed results included repeated `4625` failures followed later by `4624` events. The successful events included logon types `7` (unlock) and `11` (cached interactive logon). These events alone do **not** establish a fresh domain-controller authentication or a compromise.

For the local interactive failures, the event showed `Source_Network_Address=127.0.0.1`. This is the **loopback address** and does not identify a remote attacker. `host=WIN10-VM1` identifies the machine that generated the log.

<img width="929" height="428" alt="image" src="https://github.com/user-attachments/assets/be3abe75-0a11-4b90-9acb-d0cf80aa1af1" />

## 12. Investigation Summary

| Field | Finding |
|---|---|
| Detection | Repeated Windows failed logons |
| Affected test account | `loan.duong` |
| Reporting endpoint | `WIN10-VM1` |
| Primary evidence | Event `4625` |
| Correlated evidence | Event `4624` |
| Alert | `SOC - Brute Force Detection` |
| Alert severity | Medium (lab-configured) |
| Assessment | True detection of authorized simulated activity; no evidence of an actual attack |
| Resolution | Document the simulation and validate the detection workflow |

## 13. Outcome

This lab demonstrated centralized Windows Security log collection, SPL-based authentication analysis, scheduled alerting, and initial SOC triage. The alert was configured and verified through Splunk's Triggered Alerts interface.
