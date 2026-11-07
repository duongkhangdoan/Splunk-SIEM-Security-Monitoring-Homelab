## Overview
This lab demonstrates Linux authentication log collection, SSH failed-login analysis, brute-force detection, and scheduled alerting using Splunk Enterprise. A Windows host generates controlled failed SSH logins against an Ubuntu machine in a private homelab.

## Lab Environment
- **SIEM:** Splunk Enterprise running on Ubuntu (`splunk`)
- **Linux host:** Ubuntu, `192.168.56.104`
- **Test client:** Windows PowerShell, observed source IP `192.168.56.1`
- **Log source:** `/var/log/auth.log`
- **Splunk index:** `linux_security`
- **Sourcetype:** `linux_secure`
- **Detection threshold:** At least 5 failed SSH logins from one IP in a fixed 5-minute bucket

## Architecture
```text
Windows PowerShell (192.168.56.1)
       |
       | SSH login attempts (Host-only network)
       v
Ubuntu / OpenSSH (192.168.56.104)
       |
       v
/var/log/auth.log (rsyslog)
       |
       v
Splunk Enterprise file monitor
       |
       v
index=linux_security -> SPL detection -> Scheduled alert
```

## Implementation

### 1. Verify Linux authentication logs
Check that the authentication log exists and contains events:

```bash
sudo tail -n 20 /var/log/auth.log
ls -l /var/log/auth.log
```

<img width="800" height="602" alt="image" src="https://github.com/user-attachments/assets/c41945b7-c303-4e5a-98e2-f057dca16c0f" />

The file was owned by `syslog:adm` and readable by members of the `adm` group. Verify the account running Splunk has the necessary permissions:

```bash
ps -eo user,pid,comm | grep splunkd
id duongdoan
```

<img width="996" height="77" alt="image" src="https://github.com/user-attachments/assets/8cfb5690-dd11-45c5-8b72-12cc1fc91d48" />

### 2. Create a dedicated index
In Splunk Web, navigate to **Settings > Indexes > New Index** and create:

- **Name:** `linux_security`
- **Data type:** Events

<img width="884" height="136" alt="image" src="https://github.com/user-attachments/assets/7536b18b-dd24-42d7-8690-c78ee0880d85" />

### 3. Configure local file monitoring
Splunk Enterprise was already installed on Ubuntu under `/opt/splunk`; no Universal Forwarder was needed on the same host.

```bash
/opt/splunk/bin/splunk add monitor /var/log/auth.log -index linux_security -sourcetype linux_secure
```

<img width="882" height="84" alt="image" src="https://github.com/user-attachments/assets/4d7bb3d6-9eb8-4297-ae6f-1e3e4cdaeba9" />

Confirm ingestion in **Search & Reporting**:

```spl
index=linux_security
| stats count by index sourcetype
```

<img width="880" height="156" alt="image" src="https://github.com/user-attachments/assets/c2198d91-81c9-4f5a-8cb0-284b3d556936" />

The initial verification returned **336 authentication events**.

### 4. Generate controlled failed SSH logins
From Windows PowerShell, connect to the Ubuntu lab host:

```powershell
ssh duongdoan@192.168.56.104
```

<img width="734" height="247" alt="image" src="https://github.com/user-attachments/assets/128f6036-cdd3-4567-aafe-3de192f2a637" />

Enter an intentionally incorrect password several times, using only the authorized lab account. OpenSSH records failures in `/var/log/auth.log`.

### 5. Investigate failed logins
```spl
index=linux_security sourcetype=linux_secure "Failed password"
| table _time host _raw
| sort - _time
```

<img width="975" height="314" alt="image" src="https://github.com/user-attachments/assets/63f2ee31-949e-44d4-a35b-0a2e705ade6b" />

The observed logs identified failed attempts for `duongdoan` originating from `192.168.56.1`.

### 6. Detect SSH brute-force patterns
```spl
index=linux_security sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count by _time src_ip
| where count>=5
```

<img width="1005" height="200" alt="image" src="https://github.com/user-attachments/assets/5d32b8c2-110b-41cf-bae8-e13ee8a96ff6" />

**How it works:** Extract the source IPv4 address, group events into fixed 5-minute time buckets, count failed logins per IP, and return buckets with five or more failures.

**Observed result:** **9 failed SSH logins** from `192.168.56.1` in one 5-minute bucket.

> **Detection limitation:** `bin _time span=5m` uses fixed buckets, not a rolling five-minute window. Events spanning a bucket boundary can be split. The rule is a threshold-based indicator, not proof of a malicious attack.

### 7. Create and validate a scheduled alert
From the detection search, select **Save As > Alert** and configure:

| Setting | Value |
|---|---|
| Alert title | SSH Brute Force Detection |
| Alert type | Scheduled |
| Cron expression | `*/5 * * * *` |
| Search time range | Last 10 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger mode | Once / Digest |
| Action | Add to Triggered Alerts |
| Severity | High |

Repeat the controlled failed-login test, wait for the scheduled search, and inspect **Activity > Triggered Alerts**.

**Validated result:** A **High** severity scheduled SSH brute-force alert appeared in the Triggered Alerts list.

> A 10-minute search window can cause overlapping evaluations of the same 5-minute bucket. For production use, refine the schedule, time bounds, suppression, and detection logic to avoid duplicate or missed alerts.

<img width="975" height="314" alt="image" src="https://github.com/user-attachments/assets/4331dc52-11c2-4cb5-aa13-f7b93cc9cd0e" />
<img width="975" height="185" alt="image" src="https://github.com/user-attachments/assets/e4fdcef4-0641-4a3d-9430-cc722398e686" />

## Results
- Collected Ubuntu authentication events in a dedicated Splunk index.
- Identified SSH login failures and extracted the originating IP address.
- Detected 9 failed logins from one IP in a fixed 5-minute interval.
- Created a scheduled Splunk alert and verified that it triggered.

## Scope and Limitations
The Windows-to-Ubuntu SSH test used a **Host-only** network path, which did not traverse pfSense. Therefore, this lab **does not claim successful correlation of the SSH attempts with pfSense firewall logs**. Cross-source correlation would require traffic and logging from a shared, observable network path.

## Skills Practiced
Linux authentication logging, OpenSSH, Splunk Enterprise, log ingestion, SPL (`rex`, `bin`, `stats`, `where`), source-IP extraction, brute-force detection, scheduled alerting, and security-event investigation.
