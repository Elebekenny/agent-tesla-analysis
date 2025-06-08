# 🐍 Agent Tesla Malware Analysis Lab

## 🔍 Overview
This project demonstrates a full real-world malware analysis of **Agent Tesla**, a well-known Remote Access Trojan (RAT). The malware was analyzed in a controlled environment using both static and dynamic techniques. The goal was to extract Indicators of Compromise (IOCs), reverse engineer malicious behavior, and build custom YARA rules for detection.

---

## 🧪 Malware Sample
- **Malware Name**: Agent Tesla
- **Sample Hash**: `e3b0c44298fc1c149afbf4c8996fb924...`
- **Source**: Retrieved from [MalwareBazaar](https://bazaar.abuse.ch)

_⚠️ For safety, the actual sample is NOT included in this repository. Only hashes and analysis data are provided._

---

## ⚙️ Lab Setup
- **VM**: Windows 10 (Isolated)
- **Tools**:
  - PEStudio
  - Ghidra
  - Detect It Easy
  - Procmon
  - Wireshark
  - x64dbg
  - Fakenet-NG
  - Regshot
  - Autoruns
  - YARA
  - Cuckoo Sandbox (optional)

---

## 🔧 Static Analysis
- Analyzed headers, strings, and imports
- Found potential obfuscation (packed binary)
- Noted suspicious API calls like `GetAsyncKeyState`, `WriteProcessMemory`, and `HttpSendRequest`

### 🔗 Findings:
- Hardcoded SMTP server and credentials
- Suspicious mutex: `AgentTesla_abc123`
- Embedded configuration data in binary strings

---

## 🚦 Dynamic Analysis
- Executed inside an isolated VM with snapshot
- Monitored file system, registry, and network behavior

### 🧠 Behavior Observed:
- Keystroke logging and clipboard scraping
- Credential theft from browsers and email clients
- Network beacon to `185.62.189.43`
- Persistence via registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

---

## 🧩 IOCs Extracted
File: [`iocs.json`](./iocs.json)

```json
{
  "md5": "e3b0c44298fc1c149afbf4c8996fb924",
  "domains": ["agenttesla[.]xyz"],
  "ips": ["185.62.189.43"],
  "mutex": "AgentTesla_abc123",
  "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
}
```

---

## 🛡️ YARA Rule
File: [`yara/agenttesla.yar`](./yara/agenttesla.yar)
```yara
rule AgentTesla_Generic
{
    meta:
        description = "Detects Agent Tesla variant"
        author = "@elebekenny"
    strings:
        $s1 = "smtp.gmail.com"
        $s2 = "user=admin&pass="
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
```

---

## 🧠 MITRE ATT&CK Mapping
| Tactic              | Technique                     | ID     |
|---------------------|-------------------------------|--------|
| Initial Access      | Phishing via Attachment       | T1566  |
| Execution           | Malicious Script              | T1059  |
| Credential Access   | Credential Dumping            | T1555  |
| Persistence         | Registry Run Key              | T1547  |
| Exfiltration        | Exfiltration Over C2 Channel  | T1041  |

---

## 📝 Full Report
- [AgentTesla_Report.md](./AgentTesla_Report.md)

Includes full static/dynamic breakdown, screenshots, and analysis.

---

## 📸 Screenshots To Add (in `/screenshots/` folder)
1. PEStudio output
2. Strings view with embedded credentials
3. Wireshark C2 traffic
4. Procmon with file/registry activities
5. Autoruns persistence entry
6. Ghidra disassembly snippet

---

## 📢 Author & Credits
- **Author**: [@elebekenny](https://github.com/elebekenny)
- **Special Thanks**: MalwareBazaar, MITRE ATT&CK, REMnux, FLARE VM

> This analysis was performed for educational and research purposes in a safe, isolated lab environment. Do not attempt to run malware outside of a virtualized sandbox.

---

## 🛡️ License
This project is open-source and released under the MIT License.
