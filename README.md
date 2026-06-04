# Signal Before the Noise
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

# MITRE ATT&CK Mapping

| Technique | Description |
|------------|------------|
| T1593 | Search Open Websites/Domains |
| T1046 | Network Service Discovery |
| T1110 | Brute Force |
| T1078 | Valid Accounts |
| T1021.001 | Remote Desktop Protocol |
| T1589 | Gather Victim Identity Information |

---

# Recommendations

1. Reset credentials associated with administrative accounts.
2. Review all successful logons originating from Uruguay.
3. Restrict RDP access through Azure Bastion or VPN.
4. Enforce MFA for privileged accounts.
5. Monitor for future foreign logons.
6. Develop detections for RDP brute-force patterns.

---

# Conclusion

This threat hunt demonstrated how a seemingly harmless social media post can expose actionable infrastructure details. Investigation confirmed that the exposed virtual machine became the target of internet-wide scanning, brute-force authentication attempts, and successful RDP logons originating from an unexpected geographic region.

The findings reinforce the importance of exposure management, identity monitoring, and proactive threat hunting when investigating publicly accessible assets.
