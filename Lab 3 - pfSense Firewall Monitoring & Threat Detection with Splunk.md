## Overview

This lab implements centralized firewall monitoring with **pfSense**, **Ubuntu Linux**, and **Splunk Enterprise**. pfSense forwards firewall events over Syslog (UDP 514) to Ubuntu. Splunk monitors the received log file, extracts firewall fields, analyzes blocked connections, and generates scheduled security alerts. A controlled ICMP test validates the complete detection pipeline.

## Architecture

```text
Ubuntu test host (10.10.10.12) -- traffic --> pfSense firewall (10.10.10.1)
                                                |
                                                | Remote Syslog / UDP 514
                                                v
                                   Ubuntu syslog receiver
                                   /var/log/pfsense.log
                                                |
                                                | Splunk file monitoring
                                                v
                                   Splunk Enterprise
                                   index=pfsense
                                                |
                                                v
                                   SPL detection + scheduled alert
```

> The Splunk server and the Ubuntu log receiver were configured on the same Ubuntu machine in this lab. The SECURITY network uses the `10.10.10.0/24` range; `10.10.10.12` was the traffic-generation host shown in the firewall logs. Adjust addresses and interface names for your own environment.

## 1. Configure pfSense firewall logging

1. Sign in to the pfSense web interface at `10.10.10.1`.
2. Open **Status → System Logs → Settings** and configure remote logging to the Ubuntu syslog receiver using **UDP port 514**. Include firewall events in the forwarded log categories.
3. Under **Firewall → Rules → SECURITY**, review the rules controlling the SECURITY interface. Enable **Log packets that are handled by this rule** for rules whose matches need to be monitored, and **Save → Apply Changes**.
4. Confirm that both allowed and blocked traffic can be viewed under **Status → System Logs → Firewall**.

> Rule order matters: pfSense evaluates interface rules in order. A broad allow rule above a test block rule will allow matching traffic before the block rule can apply.

## 2. Verify Syslog reception on Ubuntu

Confirm packets arrive at the syslog receiver:

```bash
sudo tcpdump -ni enp0s3 'udp port 514'
```

<img width="697" height="277" alt="image" src="https://github.com/user-attachments/assets/96e316cb-2cbb-4f37-9eef-ae8fc542f913" />

The capture showed pfSense (`10.10.10.1`) sending UDP/514 messages to Ubuntu (`10.10.10.12`). The configured syslog service wrote these messages to:

```text
/var/log/pfsense.log
```

Verify the file and follow incoming entries:

```bash
sudo ls -l /var/log/pfsense.log
sudo tail -f /var/log/pfsense.log
```

<img width="843" height="328" alt="image" src="https://github.com/user-attachments/assets/f3ffdb48-ead1-46da-82a6-39c281282264" />

Firewall messages contain `filterlog` and comma-separated values including the action (`pass` or `block`), protocol, source address, and destination address.

## 3. Allow Splunk to read the log file

Splunk ran under the `duongdoan` account in this lab. Grant that account read access to the log file:

```bash
ps -eo user,pid,comm | grep splunkd
sudo setfacl -m u:duongdoan:r /var/log/pfsense.log
getfacl /var/log/pfsense.log
```

<img width="755" height="270" alt="image" src="https://github.com/user-attachments/assets/04a26b2c-8cfa-46bf-bcd4-a175a2e7f536" />

The ACL output confirmed `user:duongdoan:r--`.

> If the syslog service rotates or recreates the file, verify that the new file remains readable by Splunk. A persistent group/ACL strategy may be needed.

## 4. Create the Splunk index and file input

1. In Splunk Enterprise, create an event index named **`pfsense`** under **Settings → Indexes**.
2. Navigate to **Settings → Add Data → Monitor → Files & Directories**.
3. Select `/var/log/pfsense.log` and enable continuous monitoring.
4. Create/select a custom source type named **`pfsense:filterlog`**. Review the event preview and timestamp extraction.
5. Set **Host** to `splunk`, **Index** to `pfsense`, and submit the configuration.

The configuration review showed:

| Setting | Value |
|---|---|
| Input type | File Monitor |
| Source path | `/var/log/pfsense.log` |
| Continuously monitor | Yes |
| Source type | `pfsense:filterlog` |
| Host | `splunk` |
| Index | `pfsense` |  

<img width="871" height="290" alt="image" src="https://github.com/user-attachments/assets/143c01a4-83cb-4881-bb5b-43b1158355b6" />

Verify events are searchable:

```spl
index=pfsense
```

<img width="943" height="474" alt="image" src="https://github.com/user-attachments/assets/d40e9a72-47cc-4b1a-a3ab-efbeedabdd64" />

## 5. Parse and analyze pfSense firewall events

The received pfSense `filterlog` records were comma-separated. In this environment, Splunk's `split()` and `mvindex()` functions were used to extract fields. **Splunk uses zero-based indices** for `mvindex()`.

### 5.1 Extract firewall action and IP addresses

```spl
index=pfsense
| eval data=split(_raw,",")
| eval action=mvindex(data,6)
| eval src_ip=mvindex(data,18)
| eval dest_ip=mvindex(data,19)
| table _time action src_ip dest_ip
| sort - _time
```

<img width="792" height="585" alt="image" src="https://github.com/user-attachments/assets/b3546970-d038-41b1-a81f-7744314668da" />

The field positions above matched the IPv4 TCP/UDP/ICMP logs observed in this lab. They should be validated against sample raw events before reuse with different pfSense log formats.

### 5.2 Count allowed versus blocked events

```spl
index=pfsense
| eval data=split(_raw,",")
| eval action=mvindex(data,6)
| stats count by action
| sort - count
```

<img width="1523" height="1010" alt="image" src="https://github.com/user-attachments/assets/eb7f42ad-ae84-476c-ab1a-bd26a10c3942" />

An earlier verification returned **296 `pass`** and **142 `block`** events.

### 5.3 Identify top blocked source IPs

```spl
index=pfsense
| eval data=split(_raw,",")
| where mvindex(data,6)="block"
| eval src_ip=mvindex(data,18)
| stats count by src_ip
| sort - count
```

<img width="1510" height="938" alt="image" src="https://github.com/user-attachments/assets/280b6beb-f105-44a5-b4b4-0a7c1621b462" />

Observed blocked sources included `34.107.243.93`, `162.159.61.4`, `10.10.10.12`, and `10.80.80.11`.

### 5.4 Review frequently blocked destination ports

```spl
index=pfsense "block"
| eval data=split(_raw,",")
| eval dest_port=mvindex(data,21)
| stats count by dest_port
| sort - count
```

<img width="1520" height="722" alt="image" src="https://github.com/user-attachments/assets/97a437b4-fda8-40e0-90e1-ee9e4e2c1d22" />

The search produced destination-port counts including `12304`, `1475`, `443`, `50980`, `57535`, and `9997`. These are **observed port values**, not evidence by themselves of malicious activity. Port extraction at this offset applies to the matching IPv4 TCP/UDP records; ICMP uses a different layout.

### 5.5 Detect bursts of blocked traffic over five-minute windows

```spl
index=pfsense
| eval d=split(_raw,",")
| where mvindex(d,6)="block"
| eval src_ip=mvindex(d,18)
| bin _time span=5m
| stats count by _time src_ip
| where count>=5
| sort - count
```

<img width="1004" height="441" alt="image" src="https://github.com/user-attachments/assets/c8d49590-8c0b-47e5-8bda-c61af2e8b114" />

This search groups events by source IP and five-minute time bucket, returning only buckets with **five or more blocked events**.

## 6. Create a scheduled detection alert

1. Run the five-minute blocked-traffic detection query above.
2. Select **Save As → Alert**.
3. Name the alert **`pfSense - Excessive Block Connections`**.
4. Choose **Scheduled** and **Run on Cron Schedule** with expression `*/5 * * * *`.
5. Set **Time Range** to **Last 5 minutes**.
6. Set **Trigger alert when** to **Number of Results > 0**.
7. Choose **Trigger Once** and add the **Add to Triggered Alerts** action with **High** severity.
8. Save and verify that the alert is enabled.

> Because the SPL query already filters to `count>=5`, a result count greater than zero indicates at least one source met the threshold. The query's `bin _time span=5m` creates clock-aligned buckets; for an exact rolling five-minute threshold, use an appropriate rolling-window search instead.

<img width="763" height="915" alt="image" src="https://github.com/user-attachments/assets/ec20bf48-bbb9-4444-a449-3987439eb3fc" />

## 7. Generate a controlled blocked-traffic test

To test the pipeline without disrupting ordinary traffic, a temporary pfSense rule was added **above the general allow rule** on the SECURITY interface:

| Rule field | Value |
|---|---|
| Action | Block |
| Interface | SECURITY |
| Address family | IPv4 |
| Protocol | ICMP |
| Source | `10.10.10.12` |
| Destination | `10.99.99.11` |
| Log matching packets | Enabled |
| Description | `LAB - ICMP Block Test` |

After **Save → Apply Changes**, generate ten ICMP requests from the Ubuntu test host:

```bash
ping -c 10 -i 1 10.99.99.11
```

The pfSense firewall log showed **10 blocked ICMP events** from `10.10.10.12` to `10.99.99.11`, between approximately **19:15:54 and 19:16:03 EST** on November 6, 2026.

## 8. Verify the test events in Splunk

```spl
index=pfsense
| eval d=split(_raw,",")
| where mvindex(d,6)="block"
| eval src_ip=mvindex(d,18)
| eval dest_ip=mvindex(d,19)
| search src_ip="10.10.10.12" dest_ip="10.99.99.11"
| stats count by src_ip dest_ip
```

<img width="975" height="215" alt="image" src="https://github.com/user-attachments/assets/c5f187a9-0dfa-4963-b65f-8ceff878250a" />


**Observed result:**

| src_ip | dest_ip | count |
|---|---|---:|
| `10.10.10.12` | `10.99.99.11` | **10** |

This confirmed the events passed through the firewall, Syslog receiver, monitored file, and Splunk index.

## 9. Confirm automated alerting

Open **Activity → Triggered Alerts**. At **19:20:01 EST on November 6, 2026**, Splunk displayed the following triggered alerts:

- `pfSense - Excessive Block Connections` — **High**
- `pfSense - Excessive Blocked Connections` — **High**
  
<img width="975" height="235" alt="image" src="https://github.com/user-attachments/assets/1cfa1066-3d3c-40cd-b7bd-cb3790a58685" />

Both were scheduled alerts. The visible alert records confirm triggering; the alert's **View Results** page can be used to inspect the exact matching events and determine whether both alerts are necessary.

## 10. Clean up the test

After validation, **disable or delete the temporary ICMP block rule** and apply the firewall changes. Keep the intended production/lab monitoring rules and Splunk alert enabled. Optionally consolidate the two similarly named alerts to avoid duplicate notifications.

## Results and skills demonstrated

- Centralized pfSense firewall log collection with remote Syslog over UDP 514
- Linux log-file access management with ACLs
- Splunk file monitoring, source types, and index configuration
- SPL event parsing, field extraction, aggregation, and time bucketing
- Analysis of allowed/blocked traffic, source IPs, and destination ports
- Threshold-based detection and scheduled alert configuration
- End-to-end validation with controlled ICMP traffic

**Outcome:** Successfully ingested pfSense firewall events into Splunk, identified **10 controlled blocked ICMP events**, and verified **High-severity scheduled alerts** in Splunk's Triggered Alerts view.
