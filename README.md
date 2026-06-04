# Signals Before the Noise
### Threat Hunt Report

**Author:** Sid Taha  
**Platform:** Microsoft Sentinel / Microsoft Defender XDR  
**Scenario Type:** Proactive Threat Hunt

---

# Executive Summary

A publicly shared LinkedIn post exposed Azure infrastructure details belonging to PHTG, including a public IP address, virtual machine name, operating system details, and network configuration. The objective of this hunt was to determine whether the exposed information resulted in reconnaissance, authentication attacks, or successful unauthorized access.

Investigation revealed:

- 194 public RDP targeting events
- 173 unique source IPs
- 693 external authentication attempts
- 646 failed RDP logons
- Successful RDP authentication activity originating from Uruguay
- Successful logons using the account `vmadminusername`
- Execution of a Meterpreter payload disguised as an internal document

These findings suggest the exposed asset became the target of internet-wide reconnaissance and credential attacks following public disclosure.

---

# Background

PHTG recently deployed an internal application called HealthCloud. A member of the cloud engineering team publicly posted a workstation photo on LinkedIn that unintentionally exposed Azure infrastructure details. The photo is shown below:

<img width="297" height="600" alt="Screenshot 2026-06-04 at 6 14 06 PM" src="https://github.com/user-attachments/assets/85a00853-9cc5-412f-9922-3d6914a3b7fa" />

<img width="599" height="437" alt="Screenshot 2026-06-04 at 6 15 03 PM" src="https://github.com/user-attachments/assets/a2f8fbb9-4aed-486b-9b5f-b06b3b650b3c" />

Visible information included:

- VM hostname
- Public IP address
- Internal IP address
- Azure networking details
- Resource group information
- Operating system details

The objective of the hunt was to determine whether attackers identified and acted upon the exposed information.

---

# Phase 1 – OSINT Exposure Analysis

## Objective

Identify what information was exposed through the public LinkedIn image.

## Findings

| Artifact | Value |
|-----------|-----------|
| VM Name | azwks-phtg-02 |
| Public IP | 74.249.82.162 |
| Internal IP | 10.0.0.152 |
| Operating System | Windows 10 Enterprise |

The public IP address represented the most actionable exposure because it provided attackers with a directly reachable target.

---

# Phase 2 – Reconnaissance Activity

## Objective

Determine whether external actors interacted with the exposed system.

## KQL Query

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| summarize Count=count() by LocalPort
| order by Count desc
```

## Findings

Analysis identified port **3389 (RDP)** as the most significant externally targeted service.

| Metric | Count |
|----------|----------|
| Public RDP Events | 194 |
| Unique Source IPs | 173 |

The volume of activity suggested widespread automated reconnaissance.

---

# Phase 3 – Source Diversity Analysis

## Objective

Identify how many unique internet hosts targeted the exposed RDP service.

## KQL Query

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where RemoteIPType == "Public"
| distinct RemoteIP
| count
```

## Findings

A total of **173 unique public IP addresses** targeted the exposed RDP service.

This level of source diversity is consistent with internet-wide scanning activity.

---

# Phase 4 – Connection Outcome Analysis

## Objective

Identify source IPs that successfully established TCP communication with the exposed RDP service.

## KQL Query

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt","InboundConnectionAccepted")
| summarize Actions = make_set(ActionType) by RemoteIP
| where array_length(Actions) == 2
| count
```

## Findings

57 source IPs both:

- Attempted a connection
- Received an accepted response

This suggests active interaction with the exposed RDP service rather than simple port probing.

---

# Phase 5 – Geographic Enrichment

## Objective

Determine the geographic distribution of RDP activity.

## KQL Query

```kql
let GeoTable =
externaldata(
network:string,
geoname_id:long,
continent_code:string,
continent_name:string,
country_iso_code:string,
country_name:string
)
["https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv"];

DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_iso_code
| count
```

## Findings

- 11 countries associated with accepted RDP connections
- 17 countries associated with RDP authentication activity

---

# Phase 6 – Authentication Analysis

## Objective

Determine whether reconnaissance activity progressed into credential attacks.

## KQL Query

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| count
```

## Findings

A total of **693 external authentication events** were observed.

---

## Authentication Breakdown

### KQL Query

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| summarize Count=count() by LogonType, ActionType
| order by LogonType asc
```

### Results

| Logon Type | Action | Count |
|------------|---------|---------|
| Network | LogonFailed | 646 |
| Network | LogonSuccess | 21 |
| RemoteInteractive | LogonSuccess | 8 |

Most common outcome:

```text
LogonFailed
```

Most common failure reason:

```text
InvalidUserNameOrPassword
```

The activity pattern strongly indicates brute-force or password-spraying behavior.

---

# Phase 7 – Successful Authentication Investigation

## Objective

Identify successful authentication activity originating from unexpected locations.

## KQL Query

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where LogonType in ("Network","RemoteInteractive")
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name
```

## Findings

Successful RDP authentication activity originated from:

- United States
- Uruguay

Because PHTG operates exclusively in the United States, Uruguay was identified as anomalous.

---

# Phase 8 – Account Attribution

## Objective

Identify the account associated with successful foreign authentication activity.

## KQL Query

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where LogonType in ("Network","RemoteInteractive")
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
```

## Findings

Successful logons from Uruguay utilized:

```text
vmadminusername
```

A total of **23 successful RDP authentication events** originated from Uruguay.

---

# Phase 9 – Post-Compromise Activity

## Objective

Determine whether the successful RDP authentication resulted in interactive user activity.

## Findings

Following the first successful authentication from Uruguay, several routine Windows and browser processes were observed. Most were identified as normal session startup activity and Microsoft Edge helper processes.

The first process that clearly indicated purposeful user interaction was:

```text
notepad.exe
```

Unlike browser child processes, Notepad is not typically launched automatically during logon and represents the first clear sign of direct operator interaction with the compromised system.

### KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-11T20:38:00Z) .. datetime(2025-12-11T20:50:00Z))
| order by TimeGenerated asc
```

---

# Phase 10 – Internal Reconnaissance

## Objective

Identify files accessed by the attacker following initial access.

## Findings

Multiple text documents were opened during the session. One file stood out as particularly valuable from an attacker perspective:

```text
notes_sarah.txt
```

The file appeared to contain internal engineer notes and operational information.

Documents of this type frequently contain:

- Password references
- Internal hostnames
- VPN information
- Administrative shortcuts
- Troubleshooting procedures

Such information can significantly reduce attacker effort during post-compromise operations.

---

# Phase 11 – Malware Staging

## Objective

Determine whether malicious files were introduced onto the system.

## Findings

Investigation revealed a suspicious file rename sequence:

```text
Sarah_Chen_Notes.txt
```

↓

```text
Sarah_Chen_Notes.exe.txt
```

↓

```text
Sarah_Chen_Notes.exe
```

This sequence demonstrates classic double-extension evasion designed to disguise an executable as a benign text document.

### KQL Query

```kql
DeviceFileEvents
| where ActionType == "FileRenamed"
| where PreviousFileName contains "Sarah"
| project TimeGenerated, PreviousFileName, FileName
| order by TimeGenerated asc
```

### MITRE ATT&CK

| Technique | Description |
|------------|------------|
| T1036 | Masquerading |

---

# Phase 12 – Payload Identification

## Objective

Identify the malware payload.

## Findings

SHA256 analysis identified the malicious payload:

```text
224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695
```

Tracking the hash across rename events revealed the complete file lifecycle:

```text
Sarah_Chen_Notes.txt
→ Sarah_Chen_Notes.exe.txt
→ Sarah_Chen_Notes.exe
→ PHTG.exe
```

### Malware Classification

Microsoft Defender classified the sample as:

```text
Meterpreter
```

This classification indicates the payload was associated with a post-exploitation framework commonly used for remote access and command execution.

---

# Phase 13 – Defender Evasion

## Objective

Determine why the malware was able to execute.

## Findings

Microsoft Defender detected and quarantined the payload multiple times.

However, the payload later executed successfully because Defender was operating in:

```text
passive Mode
```

Telemetry indicated:

```text
ReportSource:
Windows Defender Antivirus passive mode
```

Passive mode allowed detection events to occur without active prevention or blocking.

### MITRE ATT&CK

| Technique | Description |
|------------|------------|
| T1562.001 | Impair Defenses |

---

# Phase 14 – Persistence Mechanism

## Objective

Identify how the malware maintained execution.

## Findings

The malware executed in two phases.

### Initial Execution

```text
Sarah_Chen_Notes.exe
```

### Persistence Phase

```text
PHTG.exe
```

Later executions were launched through:

```text
cmd.exe
```

using the following batch file:

```text
C:\ProgramData\PHTG\HealthCloud\Launch.bat
```

This indicates the attacker repurposed existing HealthCloud infrastructure to disguise malicious activity.

### KQL Query

```kql
DeviceProcessEvents
| where FileName == "PHTG.exe"
| project TimeGenerated,
         FileName,
         InitiatingProcessFileName,
         InitiatingProcessCommandLine
```

### MITRE ATT&CK

| Technique | Description |
|------------|------------|
| T1547 | Boot or Logon Autostart Execution |

---

# Phase 15 – Command and Control Activity

## Objective

Identify post-exploitation network communications.

## Findings

Following execution, the malware established outbound communications to:

```text
173.244.55.130
```

Connection details:

| Artifact | Value |
|-----------|-----------|
| Process | PHTG.exe |
| Remote IP | 173.244.55.130 |
| Remote Port | 4444 |
| Country | Uruguay |
| Continent | South America |

Port 4444 is commonly associated with Meterpreter reverse-shell activity.

### KQL Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "PHTG.exe"
| project TimeGenerated,
         RemoteIP,
         RemotePort,
         InitiatingProcessFileName
```

### MITRE ATT&CK

| Technique | Description |
|------------|------------|
| T1071 | Application Layer Protocol |
| T1105 | Ingress Tool Transfer |
| T1071.001 | Web Protocols |

---

# Phase 16 – Abuse of Legitimate Infrastructure

## Findings

Rather than creating an entirely new persistence location, the attacker hid malware inside an existing directory associated with the recently deployed HealthCloud service.

Observed location:

```text
C:\ProgramData\PHTG\HealthCloud\
```

Legitimate files associated with HealthCloud were observed prior to malware activity, indicating the attacker leveraged trusted infrastructure already present on the host.

This allowed malicious files to blend into normal application activity and reduced the likelihood of detection.

### MITRE ATT&CK

| Technique | Description |
|------------|------------|
| T1036.005 | Match Legitimate Name or Location |

---

# MITRE ATT&CK Mapping

| Technique | Description |
|------------|------------|
| T1593 | Search Open Websites/Domains |
| T1046 | Network Service Discovery |
| T1110 | Brute Force |
| T1078 | Valid Accounts |
| T1021.001 | Remote Desktop Protocol |
| T1036 | Masquerading |
| T1036.005 | Match Legitimate Name or Location |
| T1562.001 | Impair Defenses |
| T1547 | Boot or Logon Autostart Execution |
| T1071 | Application Layer Protocol |
| T1105 | Ingress Tool Transfer |

---

# Recommendations

1. Restrict public exposure of administrative infrastructure and remove unnecessary internet-facing RDP services.
2. Enforce MFA for all privileged and administrative accounts.
3. Review successful authentication events originating from unexpected geographic locations.
4. Investigate systems operating with Microsoft Defender in passive mode and ensure active protection is enabled.
5. Monitor for suspicious file rename sequences involving double extensions (e.g., `.exe.txt`).
6. Alert on outbound connections to uncommon remote ports associated with command-and-control activity.
7. Review application directories for unauthorized executables or persistence mechanisms.

---

# Conclusion

This threat hunt began as an investigation into a publicly shared LinkedIn image that exposed Azure infrastructure details. Analysis revealed extensive external reconnaissance activity, including RDP scanning, brute-force authentication attempts, and successful authentication events originating from Uruguay.

Following successful access, the attacker interacted with the system, reviewed internal files, staged a malicious payload using a double-extension masquerading technique, and executed malware later identified by Microsoft Defender as Meterpreter. The payload was ultimately renamed to `PHTG.exe`, executed through `Launch.bat` within the HealthCloud directory, and established outbound command-and-control communications to infrastructure located in Uruguay over TCP port 4444.

Additionally, the attacker leveraged the legitimate HealthCloud application directory to blend malicious activity into existing organizational infrastructure and maintain persistence.

This investigation demonstrates how seemingly minor information exposure can provide attackers with enough intelligence to progress from reconnaissance to compromise. The findings reinforce the importance of exposure management, identity security, endpoint protection, and proactive threat hunting when defending internet-facing assets.
