# Detection Engineering with Wazuh and Sysmon

A hands-on detection engineering project built on top of my Active Directory attack lab. I instrument a Windows endpoint with Sysmon, emulate real attacker techniques with Atomic Red Team, find the gaps in what the SIEM catches out of the box, and then write, correlate, and tune my own detection rules mapped to MITRE ATT&CK. The goal was to practice the full detection engineering lifecycle, not just install a SIEM.

**What this project demonstrates in one line:** I took a technique the SIEM was blind to, wrote a custom Wazuh rule that catches it, combined several weak signals into one high-severity correlation alert, and tuned it so it fires once instead of flooding the analyst.

---

## Skills demonstrated

- **Endpoint instrumentation:** Sysmon (SwiftOnSecurity config), Wazuh agent deployment, custom log-channel collection
- **Adversary emulation:** Atomic Red Team, MITRE ATT&CK
- **Detection engineering:** authoring Wazuh rules (XML), matching on Sysmon telemetry, correlation (frequency) rules, false-positive and duplicate tuning
- **Troubleshooting:** methodically isolating why a rule did not fire across the whole pipeline
- **SOC analysis thinking:** severity-based triage, alert fatigue, duplicate vs false positive

---

## The detection engineering lifecycle

This project follows the loop a detection engineer actually runs, and the README is organized around it:

1. **Instrument** the endpoint so the right telemetry exists.
2. **Emulate** a known technique safely.
3. **Observe** what the SIEM catches, and what it misses.
4. **Detect** the gaps by writing custom rules.
5. **Correlate** weak signals into strong ones.
6. **Tune** to cut noise without losing the signal.

---

## Environment

Built on my existing lab (Wazuh SIEM already deployed). This project adds endpoint telemetry and detection content.

| Host | Role | OS |
|------|------|----|
| Wazuh | SIEM: indexer, manager, dashboard | Ubuntu Server |
| PC01 | Domain-joined workstation, the monitored endpoint and the "victim" | Windows 11 |

> Screenshot to add: the Wazuh Endpoints page showing PC01 active.

---

## 1. Instrument: Sysmon and the Wazuh agent

Windows' native logs record outcomes but miss a lot of attacker behavior. **Sysmon** adds rich endpoint telemetry (process creation with full command line and parent process, network connections, file writes). I installed Sysmon with the community SwiftOnSecurity config, which tunes what to log:

```powershell
# in C:\Windows temp, as Administrator
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath . -Force
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
./Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Sysmon writes to its own event channel, which the Wazuh agent does not collect by default. I added that channel to the agent config (`ossec.conf`) so the telemetry flows to the SIEM:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

> Screenshot to add: Threat Hunting showing `rule.groups:sysmon` events arriving from PC01.

---

## 2. Emulate and observe: validating built-in coverage

Before writing anything, I checked what Wazuh already catches, using **Atomic Red Team** to run real ATT&CK techniques safely.

**Test: T1136.001, Create Account (local).** The atomic test runs `net user /add` to create a backdoor account.

The account creation actually failed (password policy rejected it), **but Wazuh still fired a Level 12 alert** (rule 92040, "net1.exe executed a user creation command").

**Key lesson:** the native Windows "account created" event (4720) never fired, because no account was created. The only reason this was detected is that **Sysmon recorded the command being run**, not just the outcome. Sysmon detects the *attempt*, not only success. This is exactly why endpoint telemetry matters.

> Screenshot to add: the rule 92040 (Level 12) alert for the create-account attempt.

---

## 3. Detect: finding and filling gaps

Attackers run reconnaissance commands immediately after landing on a host. These are normal admin tools, so the SIEM ignores them by default. I confirmed the gap, then closed it.

**Confirming the gap:** running `whoami` produced **zero alerts**. Sysmon recorded it, but no rule matched, so as an analyst I was blind to it.

> Screenshot to add: "No results" when searching for whoami before the rule existed.

**Filling the gap:** I wrote custom rules in `local_rules.xml` (the file reserved for user rules, which survives Wazuh upgrades). Each matches a Sysmon process-creation event (Event ID 1) for a specific recon tool and maps to its ATT&CK technique:

```xml
<group name="sysmon,local,discovery_recon,">
  <rule id="100010" level="8">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)whoami\.exe</field>
    <description>Reconnaissance: whoami executed (System Owner/User Discovery - T1033)</description>
    <mitre><id>T1033</id></mitre>
  </rule>
  <rule id="100011" level="6">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)systeminfo\.exe</field>
    <description>Reconnaissance: systeminfo executed (System Information Discovery - T1082)</description>
    <mitre><id>T1082</id></mitre>
  </rule>
  <rule id="100012" level="6">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)ipconfig\.exe</field>
    <description>Reconnaissance: ipconfig executed (System Network Configuration Discovery - T1016)</description>
    <mitre><id>T1016</id></mitre>
  </rule>
  <rule id="100013" level="6">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)netstat\.exe</field>
    <description>Reconnaissance: netstat executed (System Network Connections Discovery - T1049)</description>
    <mitre><id>T1049</id></mitre>
  </rule>
</group>
```

After a ruleset reload, running each command produced a clean, named, ATT&CK-mapped alert.

> Screenshot to add: rule 100010 firing with its "Reconnaissance: whoami executed" description, and/or the rule 100010 definition page showing the MITRE mapping.

**Design choice worth noting:** I match on `originalFileName` (the name baked into the file's metadata) rather than the path, because it survives a rename. An attacker who renames `whoami.exe` to `notepad.exe` still gets caught, because the metadata does not change.

---

## 4. Debug: when a rule does not fire

One rule (systeminfo, 100011) did not fire, and tracking down why was the most valuable part of the project. I ruled out each layer in turn:

- **Rule reloaded?** Verified the loaded rule showed the correct pattern.
- **Pipeline working?** Re-ran `whoami`; its rule fired instantly, so the pipeline was healthy.
- **Manager healthy?** Checked daemon status; analysisd and remoted were running.
- **Event being generated?** Queried the Sysmon log directly and confirmed systeminfo was recorded.

The event existed and reached the SIEM, but the rule still missed. Inspecting the raw Sysmon event revealed the cause:

```
Image:            C:\Windows\System32\systeminfo.exe
OriginalFileName: sysinfo.exe
```

`systeminfo.exe` has the metadata name **`sysinfo.exe`**, not "systeminfo.exe". My pattern looked for the wrong string. Even after correcting the pattern to match `sysinfo`, the `originalFileName` match did not work reliably for this binary, while matching the `image` field did.

**Lesson:** the theoretically better field (metadata name, rename-resistant) is only better if it actually populates and matches. You validate your assumptions against real events rather than trusting them. This is the difference between a rule that looks right and a rule that works.

> Screenshot to add: the raw Sysmon event showing `OriginalFileName: sysinfo.exe`.

---

## 5. Correlate: turning weak signals into a strong one

A single recon command is low signal. Several in a short window from one host is a strong signal of active reconnaissance. I tagged the four discovery rules with a shared group (`discovery_recon`) and wrote a **correlation rule** that counts them:

```xml
<group name="local,correlation,">
  <rule id="100020" level="12" frequency="3" timeframe="120" ignore="300">
    <if_matched_group>discovery_recon</if_matched_group>
    <description>Multiple discovery commands from one host within 2 minutes (possible active reconnaissance)</description>
    <mitre><id>T1082</id></mitre>
  </rule>
</group>
```

- `frequency="3" timeframe="120"`: fire when three discovery alerts occur within 120 seconds.
- `level="12"`: high severity, because the pattern (not any single command) is the threat.

Running four recon commands together produced the individual Level 6 to 8 alerts **plus** one Level 12 "possible active reconnaissance" alert. That high alert is what a real analyst, who filters by severity rather than scrolling, would actually see.

> Screenshot to add: rule 100020 (Level 12) firing alongside the individual discovery alerts.

---

## 6. Tune: cut noise without losing signal

The correlation rule first fired **multiple times** for a single recon burst (once per additional command past the threshold). Duplicate alerts for the same activity add no information and cause alert fatigue. I tuned it with one setting:

```
ignore="300"
```

After firing, the rule stays quiet for 300 seconds, so one recon burst now produces exactly **one** high alert regardless of how many commands the attacker runs.

**The distinction that matters:**
- A **duplicate** is the same true alert repeated (fixed here with `ignore`).
- A **false positive** is an alert on benign activity (e.g., an admin legitimately troubleshooting), fixed differently, by adding context or exceptions.

**The judgment that matters:** tuning can go too far. Too long an `ignore` could suppress a genuinely new wave of activity. The craft is cutting duplicates *without* blinding yourself. `300` seconds balances the two for a recon burst.

> Screenshot to add: before tuning (two 100020 alerts for one burst) and after (one alert).

---

## Detection catalog

| Rule ID | Detection | ATT&CK technique | ATT&CK ID | Level | Data source | How validated |
|---------|-----------|------------------|-----------|-------|-------------|---------------|
| 92040 (built-in) | Local account creation command | Create Account | T1136.001 | 12 | Sysmon EID1 | Atomic Red Team T1136.001-4 |
| 100010 | `whoami` executed | System Owner/User Discovery | T1033 | 8 | Sysmon EID1 | manual run |
| 100011 | `systeminfo` executed | System Information Discovery | T1082 | 6 | Sysmon EID1 | manual run (field debugged) |
| 100012 | `ipconfig` executed | System Network Config Discovery | T1016 | 6 | Sysmon EID1 | manual run |
| 100013 | `netstat` executed | System Network Connections Discovery | T1049 | 6 | Sysmon EID1 | manual run |
| 100020 | Multiple discovery commands (recon burst) | Discovery (correlation) | T1082 | 12 | correlation of 100010-100013 | manual run, tuned with `ignore` |

---

## Key takeaways

- Endpoint telemetry (Sysmon) catches attacker *behavior*, including attempts that never produce a native Windows security event.
- Writing a detection is easy; validating that it actually fires, across the whole pipeline, is the real skill.
- Correlation rules are how a SOC finds the needle: they turn scattered weak signals into one high-severity alert an analyst will actually triage.
- Tuning is not just "make it quieter," it is "make it quieter without losing signal."

## Limitations and next steps

This covers a handful of discovery techniques on one endpoint. Natural extensions:
- Extend Sysmon and these detections to the Domain Controller.
- Add detections for later ATT&CK stages (credential access, lateral movement, persistence).
- Add a network layer (Suricata IDS on pfSense) and correlate network alerts with these host detections.

## A note on sanitization

This lab runs on an isolated private network. Internal IP addresses are internal-only RFC1918 addresses. No real credentials appear in this writeup.
