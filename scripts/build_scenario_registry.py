#!/usr/bin/env python3
"""Build and synchronize catalog/provenance.json and catalog/scenarios.json.

Generates the complete scenario and provenance registry across all 13 reference sources
mapped to canonical COPS scenarios and supporting material.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"


def build_registry() -> None:
    now_utc = "2026-10-02T23:00:00Z"

    # Preserve the compact source inventory rows until that generated catalog is migrated.
    # fmt: off
    # --- 1. S01: command-cheatsheet (135 items) ---
    s01_items = [
        # Network Recon & Discovery (22)
        ("s01-001", "recon/nmap.md", "scenario", "COPS-E01.01-S01", "Network port and service mapping"),
        ("s01-002", "recon/masscan.md", "scenario", "COPS-E04.02-S01", "High-speed port scanner"),
        ("s01-003", "recon/rustscan.md", "scenario", "COPS-E04.02-S01", "Adaptive port discovery"),
        ("s01-004", "recon/arp-scan.md", "scenario", "COPS-E12.02-S01", "Local ARP discovery"),
        ("s01-005", "recon/netdiscover.md", "scenario", "COPS-E12.02-S01", "Passive and active ARP network scanner"),
        ("s01-006", "recon/unicornscan.md", "scenario", "COPS-E04.02-S01", "Userland distributed TCP/UDP scanner"),
        ("s01-007", "recon/ping-sweep.md", "scenario", "COPS-E04.02-S01", "ICMP echo sweep procedures"),
        ("s01-008", "recon/traceroute.md", "scenario", "COPS-E04.02-S01", "Layer 3 hop analysis"),
        ("s01-009", "recon/hping3.md", "scenario", "COPS-E04.02-S01", "Custom packet crafting and probing"),
        ("s01-010", "recon/dnsrecon.md", "scenario", "COPS-E04.01-S01", "DNS enumeration and zone transfer checks"),
        ("s01-011", "recon/fierce.md", "scenario", "COPS-E04.01-S01", "DNS reconnaissance tool for locating non-contiguous IP space"),
        ("s01-012", "recon/dnsenum.md", "scenario", "COPS-E04.01-S01", "Multithreaded script for DNS enumerating"),
        ("s01-013", "recon/dig.md", "scenario", "COPS-E04.01-S01", "DNS lookup and zone transfer verification"),
        ("s01-014", "recon/sublist3r.md", "scenario", "COPS-E04.01-S01", "Fast subdomains enumeration tool"),
        ("s01-015", "recon/amass.md", "scenario", "COPS-E04.01-S01", "In-depth attack surface mapping and asset discovery"),
        ("s01-016", "recon/assetfinder.md", "scenario", "COPS-E04.01-S01", "Find domains and subdomains related to a given domain"),
        ("s01-017", "recon/subfinder.md", "scenario", "COPS-E04.01-S01", "Fast passive subdomain discovery tool"),
        ("s01-018", "recon/findomain.md", "scenario", "COPS-E04.01-S01", "Cross-platform subdomain finder"),
        ("s01-019", "recon/gobuster-dns.md", "scenario", "COPS-E04.01-S01", "DNS subdomain brute-forcing"),
        ("s01-020", "recon/censys.md", "scenario", "COPS-E04.01-S01", "Passive certificate transparency and asset search"),
        ("s01-021", "recon/shodan.md", "scenario", "COPS-E04.01-S01", "Passive search engine for Internet-connected devices"),
        ("s01-022", "recon/censys-cli.md", "scenario", "COPS-E04.01-S01", "CLI integration for Censys API querying"),

        # Web Discovery & Fuzzing (18)
        ("s01-023", "web/gobuster-dir.md", "scenario", "COPS-E05.01-S01", "Directory and file brute-forcing"),
        ("s01-024", "web/ffuf.md", "scenario", "COPS-E05.01-S01", "Fast web fuzzer for endpoints and headers"),
        ("s01-025", "web/wfuzz.md", "scenario", "COPS-E05.01-S01", "Web application fuzzer"),
        ("s01-026", "web/dirsearch.md", "scenario", "COPS-E05.01-S01", "Web path scanner"),
        ("s01-027", "web/nikto.md", "scenario", "COPS-E05.01-S01", "Web server scanner for dangerous files/CGIs"),
        ("s01-028", "web/wpscan.md", "scenario", "COPS-E05.01-S01", "WordPress security scanner"),
        ("s01-029", "web/joomscan.md", "scenario", "COPS-E05.01-S01", "Joomla vulnerability scanner"),
        ("s01-030", "web/droopescan.md", "scenario", "COPS-E05.01-S01", "Plugin-based scanner for Drupal/Silverstripe"),
        ("s01-031", "web/whatweb.md", "scenario", "COPS-E05.01-S01", "Next generation web scanner identifying CMS and technologies"),
        ("s01-032", "web/wafw00f.md", "scenario", "COPS-E05.01-S01", "Web Application Firewall fingerprinting tool"),
        ("s01-033", "web/commix.md", "scenario", "COPS-E05.03-S01", "Automated command injection exploiter"),
        ("s01-034", "web/sqlmap.md", "scenario", "COPS-E05.03-S01", "Automatic SQL injection tool"),
        ("s01-035", "web/arjun.md", "scenario", "COPS-E05.01-S01", "HTTP parameter discovery suite"),
        ("s01-036", "web/paramspider.md", "scenario", "COPS-E05.01-S01", "Mining parameters from dark corners of Web Archives"),
        ("s01-037", "web/x8.md", "scenario", "COPS-E05.01-S01", "Hidden parameter discovery tool"),
        ("s01-038", "web/gau.md", "scenario", "COPS-E05.01-S01", "GetAllUrls fetches known URLs from alienvault, wayback"),
        ("s01-039", "web/waybackurls.md", "scenario", "COPS-E05.01-S01", "Fetch all URLs that the Wayback Machine knows"),
        ("s01-040", "web/katana.md", "scenario", "COPS-E05.01-S01", "Next-generation crawling and spidering framework"),

        # Web Vulnerabilities (24)
        ("s01-041", "web-vulns/sqli-auth-bypass.md", "scenario", "COPS-E05.02-S01", "SQL injection authentication bypass"),
        ("s01-042", "web-vulns/sqli-union.md", "scenario", "COPS-E05.03-S01", "UNION-based SQL injection extraction"),
        ("s01-043", "web-vulns/sqli-blind.md", "scenario", "COPS-E05.03-S01", "Boolean and time-based blind SQL injection"),
        ("s01-044", "web-vulns/xss-reflected.md", "scenario", "COPS-E05.06-S01", "Reflected cross-site scripting validation"),
        ("s01-045", "web-vulns/xss-stored.md", "scenario", "COPS-E05.06-S01", "Stored cross-site scripting audit"),
        ("s01-046", "web-vulns/xss-dom.md", "scenario", "COPS-E05.06-S01", "DOM-based client vulnerability analysis"),
        ("s01-047", "web-vulns/ssrf-basic.md", "scenario", "COPS-E05.05-S01", "Server-side request forgery basic validation"),
        ("s01-048", "web-vulns/ssrf-cloud-metadata.md", "scenario", "COPS-E05.05-S01", "SSRF targeting cloud metadata endpoints (169.254.169.254)"),
        ("s01-049", "web-vulns/ssti-jinja.md", "scenario", "COPS-E05.03-S01", "Server-side template injection in Jinja2"),
        ("s01-050", "web-vulns/ssti-mako.md", "scenario", "COPS-E05.03-S01", "Server-side template injection in Mako templates"),
        ("s01-051", "web-vulns/file-upload-bypass.md", "scenario", "COPS-E05.04-S01", "Arbitrary file upload extension and MIME bypass"),
        ("s01-052", "web-vulns/lfi-path-traversal.md", "scenario", "COPS-E05.04-S01", "Local file inclusion directory traversal"),
        ("s01-053", "web-vulns/lfi-php-wrappers.md", "scenario", "COPS-E05.04-S01", "LFI using PHP stream filters and data wrappers"),
        ("s01-054", "web-vulns/lfi-log-poisoning.md", "scenario", "COPS-E05.04-S01", "LFI via access log injection"),
        ("s01-055", "web-vulns/rfi-inclusion.md", "scenario", "COPS-E05.04-S01", "Remote file inclusion testing"),
        ("s01-056", "web-vulns/xxe-injection.md", "scenario", "COPS-E05.03-S01", "XML external entity injection and entity resolution"),
        ("s01-057", "web-vulns/cors-misconfig.md", "scenario", "COPS-E05.06-S01", "Cross-origin resource sharing wildcard and null origin checks"),
        ("s01-058", "web-vulns/csrf-poc.md", "scenario", "COPS-E05.06-S01", "Cross-site request forgery validation"),
        ("s01-059", "web-vulns/jwt-none-alg.md", "scenario", "COPS-E05.02-S01", "JSON Web Token none algorithm bypass"),
        ("s01-060", "web-vulns/jwt-weak-secret.md", "scenario", "COPS-E05.02-S01", "HMAC secret brute-forcing for JWT tokens"),
        ("s01-061", "web-vulns/idor-parameter-tampering.md", "scenario", "COPS-E05.02-S01", "Insecure direct object reference authorization testing"),
        ("s01-062", "web-vulns/cmd-injection-filter-bypass.md", "scenario", "COPS-E05.03-S01", "OS command injection evasion techniques"),
        ("s01-063", "web-vulns/des-java-ysoserial.md", "scenario", "COPS-E05.03-S01", "Insecure Java object deserialization gadgets"),
        ("s01-064", "web-vulns/des-python-pickle.md", "scenario", "COPS-E05.03-S01", "Python pickle unsafe deserialization payload verification"),

        # Network Services & Daemons (22)
        ("s01-065", "services/smb-enum-shares.md", "scenario", "COPS-E04.04-S01", "SMB share enumeration and permissions"),
        ("s01-066", "services/smb-null-session.md", "scenario", "COPS-E04.04-S01", "SMB IPC$ null session accessibility"),
        ("s01-067", "services/smb-cve-2017-0143.md", "scenario", "COPS-E04.04-S01", "MS17-010 EternalBlue vulnerability detection"),
        ("s01-068", "services/smb-cve-2020-0796.md", "scenario", "COPS-E04.04-S01", "SMBGhost SMBv3 compression vulnerability detection"),
        ("s01-069", "services/rpc-enum.md", "scenario", "COPS-E04.03-S01", "RPC endpoint mapper (port 135) querying"),
        ("s01-070", "services/nfs-showmount.md", "scenario", "COPS-E04.04-S01", "NFS export list querying"),
        ("s01-071", "services/nfs-no-root-squash.md", "scenario", "COPS-E06.01-S01", "NFS mount with no_root_squash misconfiguration"),
        ("s01-072", "services/ftp-anonymous.md", "scenario", "COPS-E04.04-S01", "FTP anonymous authentication checks"),
        ("s01-073", "services/ftp-bounce.md", "scenario", "COPS-E04.04-S01", "FTP PORT bounce scan checks"),
        ("s01-074", "services/ssh-audit.md", "scenario", "COPS-E04.04-S01", "SSH server cipher and MAC audit"),
        ("s01-075", "services/ssh-weak-kex.md", "scenario", "COPS-E04.04-S01", "SSH legacy key exchange detection"),
        ("s01-076", "services/rdp-nla-check.md", "scenario", "COPS-E04.04-S01", "RDP Network Level Authentication enforcement"),
        ("s01-077", "services/rdp-cve-2019-0708.md", "scenario", "COPS-E04.04-S01", "BlueKeep RDP vulnerability probe"),
        ("s01-078", "services/snmp-walk.md", "scenario", "COPS-E04.03-S01", "SNMP MIB walk for system context"),
        ("s01-079", "services/snmp-community-brute.md", "scenario", "COPS-E04.03-S01", "SNMP community string dictionary check"),
        ("s01-080", "services/ldap-anonymous-bind.md", "scenario", "COPS-E07.01-S01", "LDAP anonymous rootDSE queries"),
        ("s01-081", "services/ldap-search.md", "scenario", "COPS-E07.01-S01", "LDAP search filter queries for domain objects"),
        ("s01-082", "services/smtp-user-enum.md", "scenario", "COPS-E04.06-S01", "SMTP VRFY and EXPN user enumeration"),
        ("s01-083", "services/smtp-open-relay.md", "scenario", "COPS-E04.06-S01", "SMTP unauthenticated open relay testing"),
        ("s01-084", "services/pop3-brute.md", "scenario", "COPS-E04.06-S01", "POP3 service authentication checks"),
        ("s01-085", "services/imap-brute.md", "scenario", "COPS-E04.06-S01", "IMAP service authentication checks"),
        ("s01-086", "services/telnet-banner.md", "scenario", "COPS-E04.04-S01", "Telnet unencrypted service detection"),

        # Active Directory (21)
        ("s01-087", "ad/kerbrute-user-enum.md", "scenario", "COPS-E07.02-S01", "Kerbrute pre-authentication user enumeration"),
        ("s01-088", "ad/asreproast.md", "scenario", "COPS-E07.02-S01", "AS-REP roasting for accounts without preauth"),
        ("s01-089", "ad/kerberoast.md", "scenario", "COPS-E07.02-S01", "Kerberoasting SPN registered service accounts"),
        ("s01-090", "ad/bloodhound-ingest.md", "scenario", "COPS-E07.01-S01", "BloodHound graph ingest and relationship analysis"),
        ("s01-091", "ad/sharphound-collect.md", "scenario", "COPS-E07.01-S01", "SharpHound domain object collection"),
        ("s01-092", "ad/secretsdump.md", "scenario", "COPS-E06.03-S01", "DCSync and SAM credential dumping"),
        ("s01-093", "ad/psexec-impacket.md", "scenario", "COPS-E15.02-S01", "PsExec lateral movement via service creation"),
        ("s01-094", "ad/wmiexec-impacket.md", "scenario", "COPS-E15.02-S01", "WMI command execution without service installation"),
        ("s01-095", "ad/smbexec-impacket.md", "scenario", "COPS-E15.02-S01", "SMBExec remote command execution"),
        ("s01-096", "ad/dcomexec-impacket.md", "scenario", "COPS-E15.02-S01", "DCOM-based lateral movement"),
        ("s01-097", "ad/mimikatz-logonpasswords.md", "scenario", "COPS-E06.03-S01", "LSASS memory credential extraction"),
        ("s01-098", "ad/mimikatz-dcsync.md", "scenario", "COPS-E07.02-S01", "DRSUAPI directory replication replication simulation"),
        ("s01-099", "ad/mimikatz-golden-ticket.md", "scenario", "COPS-E07.02-S01", "KRBTGT ticket-granting ticket forging"),
        ("s01-100", "ad/mimikatz-silver-ticket.md", "scenario", "COPS-E07.02-S01", "Service ticket forging for specific SPNs"),
        ("s01-101", "ad/responder-llmnr-poison.md", "scenario", "COPS-E07.03-S01", "LLMNR and NBT-NS poisoning"),
        ("s01-102", "ad/ntlm-relayx.md", "scenario", "COPS-E07.03-S01", "NTLM cross-protocol relay to LDAP/SMB"),
        ("s01-103", "ad/zero-logon-cve-2020-1472.md", "scenario", "COPS-E07.02-S01", "Netlogon cryptographic authentication bypass"),
        ("s01-104", "ad/print-nightmare-cve-2021-34527.md", "scenario", "COPS-E07.04-S01", "Print Spooler remote driver installation"),
        ("s01-105", "ad/petitpotam-cve-2021-36942.md", "scenario", "COPS-E07.03-S01", "MS-EFSR machine account authentication coerce"),
        ("s01-106", "ad/certipy-adcs-esc1.md", "scenario", "COPS-E07.04-S01", "AD CS ESC1 client authentication certificate request"),
        ("s01-107", "ad/certipy-adcs-esc8.md", "scenario", "COPS-E07.04-S01", "AD CS ESC8 NTLM relay to HTTP certificate enrollment"),

        # Linux Privilege Escalation (12)
        ("s01-108", "linux-privesc/sudo-rights.md", "scenario", "COPS-E06.01-S01", "sudo -l misconfiguration and NOPASSWD entries"),
        ("s01-109", "linux-privesc/suid-binaries.md", "scenario", "COPS-E06.01-S01", "Unusual SUID binary inspection"),
        ("s01-110", "linux-privesc/capabilities.md", "scenario", "COPS-E06.01-S01", "POSIX file capabilities (e.g. cap_setuid)"),
        ("s01-111", "linux-privesc/cron-jobs.md", "scenario", "COPS-E06.01-S01", "Writable cron scripts and schedules"),
        ("s01-112", "linux-privesc/writable-passwd.md", "scenario", "COPS-E06.01-S01", "World-writable /etc/passwd audit"),
        ("s01-113", "linux-privesc/writable-shadow.md", "scenario", "COPS-E06.01-S01", "Readable or writable /etc/shadow file check"),
        ("s01-114", "linux-privesc/dirtycow.md", "scenario", "COPS-E06.01-S01", "Kernel race condition CVE-2016-5195 check"),
        ("s01-115", "linux-privesc/dirtypipe.md", "scenario", "COPS-E06.01-S01", "Kernel pipe buffer overwrite CVE-2022-0847 check"),
        ("s01-116", "linux-privesc/nfs-root-squash.md", "scenario", "COPS-E06.01-S01", "NFS mount with root squash disabled"),
        ("s01-117", "linux-privesc/wildcard-injection.md", "scenario", "COPS-E06.01-S01", "Unix wildcard injection in tar/chown/rsync"),
        ("s01-118", "linux-privesc/path-hijack.md", "scenario", "COPS-E06.01-S01", "Relative PATH variable search order hijacking"),
        ("s01-119", "linux-privesc/shared-library-hijack.md", "scenario", "COPS-E06.01-S01", "LD_PRELOAD and RPATH shared library hijacking"),

        # Windows Privilege Escalation (10)
        ("s01-120", "win-privesc/always-install-elevated.md", "scenario", "COPS-E06.02-S01", "AlwaysInstallElevated registry policy audit"),
        ("s01-121", "win-privesc/unquoted-service-path.md", "scenario", "COPS-E06.02-S01", "Unquoted Windows service executable path review"),
        ("s01-122", "win-privesc/service-permissions.md", "scenario", "COPS-E06.02-S01", "Modifiable Windows service binary permissions"),
        ("s01-123", "win-privesc/registry-run-keys.md", "scenario", "COPS-E06.02-S01", "Writable autorun registry keys"),
        ("s01-124", "win-privesc/juicypotato.md", "scenario", "COPS-E06.02-S01", "SeImpersonatePrivilege abuse via BITS/COM"),
        ("s01-125", "win-privesc/godpotato.md", "scenario", "COPS-E06.02-S01", "SeImpersonatePrivilege abuse via DCOM"),
        ("s01-126", "win-privesc/credman-dump.md", "scenario", "COPS-E06.03-S01", "Windows Credential Manager saved credential audit"),
        ("s01-127", "win-privesc/autologon-creds.md", "scenario", "COPS-E06.03-S01", "DefaultPassword in Winlogon registry keys"),
        ("s01-128", "win-privesc/unattended-install.md", "scenario", "COPS-E06.03-S01", "Unattend.xml plaintext administrative credentials"),
        ("s01-129", "win-privesc/dll-hijacking.md", "scenario", "COPS-E06.02-S01", "Missing DLL search order hijacking"),

        # Tunneling & Wordlists (6)
        ("s01-130", "tunneling/chisel-socks.md", "scenario", "COPS-E15.02-S01", "Chisel TCP/UDP reverse SOCKS5 proxy"),
        ("s01-131", "tunneling/ligolo-ng.md", "scenario", "COPS-E15.02-S01", "Ligolo-ng TUN interface pivoting"),
        ("s01-132", "tunneling/proxychains.md", "scenario", "COPS-E15.02-S01", "Proxychains multi-hop routing"),
        ("s01-133", "passwords/john-usage.md", "supporting_guidance", "COPS-E06.03-GUIDE", "John the Ripper hash cracking modes"),
        ("s01-134", "passwords/hashcat-usage.md", "supporting_guidance", "COPS-E06.03-GUIDE", "Hashcat acceleration rules and mask attacks"),
        ("s01-135", "guidance/README.md", "supporting_guidance", "COPS-E01.01-GUIDE", "Upstream cheatsheet usage guidelines and legal constraints"),
    ]

    # --- 2. S02: Cheatsheet-God (47 text + 3 PDFs + 1 guidance = 51 items) ---
    s02_items = [
        ("s02-001", "active-directory-attacks.txt", "scenario", "COPS-E07.01-S01", "Active Directory attack methodologies"),
        ("s02-002", "ldap-queries.txt", "scenario", "COPS-E07.01-S01", "LDAP queries for user and computer enumeration"),
        ("s02-003", "kerberos-tickets.txt", "scenario", "COPS-E07.02-S01", "Kerberos ticket requests and pass-the-ticket procedures"),
        ("s02-004", "bloodhound-queries.txt", "scenario", "COPS-E07.01-S01", "Bloodhound Cypher queries for shortest domain escalation paths"),
        ("s02-005", "mimikatz-commands.txt", "scenario", "COPS-E06.03-S01", "Mimikatz memory scraping and credential extraction"),
        ("s02-006", "impacket-usage.txt", "scenario", "COPS-E15.02-S01", "Impacket protocol suite command reference"),
        ("s02-007", "responder-options.txt", "scenario", "COPS-E07.03-S01", "Responder LLMNR and NBT-NS spoofing configuration"),
        ("s02-008", "crackmapexec-commands.txt", "scenario", "COPS-E07.03-S01", "CrackMapExec credential stuffing across SMB/WinRM"),
        ("s02-009", "evil-winrm-usage.txt", "scenario", "COPS-E15.02-S01", "Evil-WinRM remote shell usage"),
        ("s02-010", "powershell-bypass.txt", "scenario", "COPS-E15.03-S01", "PowerShell execution policy and AMSI memory patch procedures"),
        ("s02-011", "lolbas-execution.txt", "scenario", "COPS-E15.03-S01", "Living Off The Land binaries for arbitrary payload execution"),
        ("s02-012", "lolbas-download.txt", "scenario", "COPS-E15.03-S01", "Living Off The Land binaries for ingress tool transfer"),
        ("s02-013", "certutil-tricks.txt", "scenario", "COPS-E15.03-S01", "Certutil file decode and ingress transfer techniques"),
        ("s02-014", "mshta-execution.txt", "scenario", "COPS-E15.03-S01", "Mshta HTA payload execution"),
        ("s02-015", "regsvr32-execution.txt", "scenario", "COPS-E15.03-S01", "Regsvr32 Squiblydoo scriptlet execution"),
        ("s02-016", "wmic-queries.txt", "scenario", "COPS-E06.02-S01", "WMIC command queries for patch and process audit"),
        ("s02-017", "windows-event-ids.txt", "supporting_guidance", "COPS-E17.02-GUIDE", "Critical security event IDs for detection mapping"),
        ("s02-018", "linux-enum-commands.txt", "scenario", "COPS-E06.01-S01", "Linux system and configuration enumeration command set"),
        ("s02-019", "gtfobins-sudo.txt", "scenario", "COPS-E06.01-S01", "GTFOBins sudo binary bypass commands"),
        ("s02-020", "gtfobins-suid.txt", "scenario", "COPS-E06.01-S01", "GTFOBins SUID binary escalation commands"),
        ("s02-021", "gtfobins-capabilities.txt", "scenario", "COPS-E06.01-S01", "GTFOBins POSIX capabilities escalation commands"),
        ("s02-022", "bash-reverse-shells.txt", "scenario", "COPS-E15.01-S01", "Bash TCP and UDP reverse shell commands"),
        ("s02-023", "python-reverse-shells.txt", "scenario", "COPS-E15.01-S01", "Python socket reverse shell one-liners"),
        ("s02-024", "php-reverse-shells.txt", "scenario", "COPS-E15.01-S01", "PHP interactive web shells and reverse connections"),
        ("s02-025", "powershell-reverse-shells.txt", "scenario", "COPS-E15.01-S01", "PowerShell Net.Sockets TCP reverse shells"),
        ("s02-026", "web-sqli-payloads.txt", "scenario", "COPS-E05.03-S01", "SQL injection payload list across DBMS vendors"),
        ("s02-027", "web-xss-payloads.txt", "scenario", "COPS-E05.06-S01", "Cross-site scripting filter evasion vectors"),
        ("s02-028", "web-ssrf-payloads.txt", "scenario", "COPS-E05.05-S01", "SSRF IP representation bypass payloads"),
        ("s02-029", "web-lfi-wordlist.txt", "scenario", "COPS-E05.04-S01", "Common Linux and Windows sensitive file paths"),
        ("s02-030", "web-ssti-payloads.txt", "scenario", "COPS-E05.03-S01", "Polyglot template injection payloads"),
        ("s02-031", "web-deserialization-tips.txt", "scenario", "COPS-E05.03-S01", "Object deserialization detection rules"),
        ("s02-032", "nmap-scan-profiles.txt", "scenario", "COPS-E04.02-S01", "Nmap timing and NSE script scanning profiles"),
        ("s02-033", "smb-enum-tools.txt", "scenario", "COPS-E04.04-S01", "SMB client tools comparison and usage"),
        ("s02-034", "snmp-mibs-oid.txt", "scenario", "COPS-E04.03-S01", "Standard SNMP OIDs for system enumeration"),
        ("s02-035", "rdp-tunneling.txt", "scenario", "COPS-E15.02-S01", "Tunneling RDP over SSH and SOCKS"),
        ("s02-036", "chisel-cheatsheet.txt", "scenario", "COPS-E15.02-S01", "Chisel client and server proxy commands"),
        ("s02-037", "ligolo-setup.txt", "scenario", "COPS-E15.02-S01", "Ligolo-ng agent and controller routing"),
        ("s02-038", "pivoting-routes.txt", "scenario", "COPS-E15.02-S01", "Linux kernel IP forwarding and iptables routing"),
        ("s02-039", "hashcat-modes.txt", "supporting_guidance", "COPS-E06.03-GUIDE", "Hashcat hash type reference codes"),
        ("s02-040", "john-rules.txt", "supporting_guidance", "COPS-E06.03-GUIDE", "John the Ripper mangling rules"),
        ("s02-041", "hydra-services.txt", "scenario", "COPS-E04.04-S01", "Hydra syntax for common network services"),
        ("s02-042", "docker-breakout-tips.txt", "scenario", "COPS-E10.07-S01", "Container escape vectors via mounted docker.sock"),
        ("s02-043", "k8s-kubectl-tricks.txt", "scenario", "COPS-E10.01-S01", "Kubectl commands for cluster discovery"),
        ("s02-044", "k8s-serviceaccount-enum.txt", "scenario", "COPS-E10.08-S01", "Service account token mounting and API interrogation"),
        ("s02-045", "forensics-memory-volatility.txt", "supporting_guidance", "COPS-E17.02-GUIDE", "Volatility memory analysis commands"),
        ("s02-046", "cve-reproduction-notes.txt", "supporting_guidance", "COPS-E14.01-GUIDE", "Safe CVE reproduction workflow constraints"),
        ("s02-047", "redteam-field-checklist.txt", "supporting_guidance", "COPS-E03.01-GUIDE", "Rules of engagement operational checklist"),
        ("s02-048", "sans-penetration-testing-cheatsheet.pdf", "supporting_guidance", "COPS-E01.01-GUIDE", "SANS pentest command reference PDF"),
        ("s02-049", "sans-sec504-hacker-tools.pdf", "supporting_guidance", "COPS-E01.01-GUIDE", "SANS hacker tools and incident handling PDF"),
        ("s02-050", "red-team-field-reference-guide.pdf", "supporting_guidance", "COPS-E01.01-GUIDE", "Red team tactical field reference PDF"),
        ("s02-051", "README.md", "supporting_guidance", "COPS-E01.01-GUIDE", "Cheatsheet-God repository guidelines"),
    ]

    # --- 3. S03 to S13 Kubernetes and Tool Articles ---
    s03_items = [
        ("s03-001", "section/hostPID", "scenario", "COPS-E10.07-S01", "Dynatrace: hostPID namespace sharing inspection"),
        ("s03-002", "section/hostNetwork", "scenario", "COPS-E10.07-S01", "Dynatrace: hostNetwork exposure analysis"),
        ("s03-003", "section/privileged", "scenario", "COPS-E10.07-S01", "Dynatrace: privileged container escape vectors"),
        ("s03-004", "section/writableRootfs", "scenario", "COPS-E10.07-S01", "Dynatrace: writable root filesystem persistence"),
        ("s03-005", "section/capabilities", "scenario", "COPS-E10.07-S01", "Dynatrace: kernel capabilities over-granting"),
    ]

    s04_items = [
        ("s04-001", "section/initial-access-api", "scenario", "COPS-E10.09-S01", "Unit 42: Exposed Kubernetes API server attacks"),
        ("s04-002", "section/execution-malicious-pod", "scenario", "COPS-E10.07-S01", "Unit 42: Deploying unauthorized container workloads"),
        ("s04-003", "section/privilege-escalation-sa", "scenario", "COPS-E10.08-S01", "Unit 42: Automated service account token abuse"),
        ("s04-004", "section/defense-evasion-daemonset", "scenario", "COPS-E10.07-S01", "Unit 42: Hiding malicious workloads via DaemonSets"),
        ("s04-005", "section/lateral-movement-etcd", "scenario", "COPS-E10.10-S01", "Unit 42: Cluster control-plane pivoting to etcd"),
    ]

    s05_items = [
        ("s05-001", "section/sa-token-leak", "scenario", "COPS-E10.08-S01", "SentinelOne: Token extraction from /var/run/secrets/"),
        ("s05-002", "section/hostpath-traversal", "scenario", "COPS-E10.07-S01", "SentinelOne: HostPath volume directory traversal to host /etc"),
        ("s05-003", "section/clusterrolebinding", "scenario", "COPS-E10.08-S01", "SentinelOne: Escalating privileges via ClusterRoleBinding creation"),
        ("s05-004", "section/node-takeover", "scenario", "COPS-E10.09-S01", "SentinelOne: Gaining control over worker node daemon"),
    ]

    s06_items = [
        ("s06-001", "section/rbac-bind", "scenario", "COPS-E10.08-S01", "Seif Rajhi: RBAC privilege escalation via 'bind' permission"),
        ("s06-002", "section/rbac-escalate", "scenario", "COPS-E10.08-S01", "Seif Rajhi: Privilege escalation via 'escalate' verb on ClusterRoles"),
        ("s06-003", "section/rbac-impersonate", "scenario", "COPS-E10.08-S01", "Seif Rajhi: Impersonating system:masters or admin service accounts"),
        ("s06-004", "section/rbac-get-secrets", "scenario", "COPS-E10.08-S01", "Seif Rajhi: Stealing cluster admin credentials via secrets/get"),
        ("s06-005", "section/rbac-create-pods", "scenario", "COPS-E10.07-S01", "Seif Rajhi: Escalation to node root via pods/create privilege"),
        ("s06-006", "section/rbac-pod-exec", "scenario", "COPS-E10.08-S01", "Seif Rajhi: Code execution in existing pods via pods/exec"),
    ]

    s07_items = [
        ("s07-001", "manifests/everything-allowed.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: Everything-allowed super-privileged pod escape"),
        ("s07-002", "manifests/privileged.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: Privileged container kernel parameter compromise"),
        ("s07-003", "manifests/hostpath.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: Root filesystem hostPath mount traversal"),
        ("s07-004", "manifests/hostpid.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: Host PID namespace injection and process inspection"),
        ("s07-005", "manifests/hostipc.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: Host IPC shared memory compromise"),
        ("s07-006", "manifests/hostnet.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: Host network namespace sniffing and loopback binding"),
        ("s07-007", "manifests/cap-sys-admin.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: CAP_SYS_ADMIN cgroup v1 release_agent escape"),
        ("s07-008", "manifests/cap-sys-ptrace.yaml", "scenario", "COPS-E10.07-S01", "Bishop Fox: CAP_SYS_PTRACE process injection on host"),
    ]

    s08_items = [
        ("s08-001", "controls/nsa-cisa-control-01", "scenario", "COPS-E10.02-S01", "Kubescape: NSA-CISA Kubernetes hardening evaluation"),
        ("s08-002", "controls/cis-benchmark", "scenario", "COPS-E10.02-S01", "Kubescape: CIS benchmark compliance scan"),
        ("s08-003", "controls/rbac-risk", "scenario", "COPS-E10.08-S01", "Kubescape: Over-permissive RBAC query evaluation"),
        ("s08-004", "controls/host-namespace-audit", "scenario", "COPS-E10.07-S01", "Kubescape: Namespace isolation compliance audit"),
        ("s08-005", "controls/api-server-audit", "scenario", "COPS-E10.09-S01", "Kubescape: Control plane API server endpoint exposure check"),
    ]

    s09_items = [
        ("s09-001", "cfg/master.yaml", "scenario", "COPS-E10.04-S01", "kube-bench: Control plane CIS benchmark checks"),
        ("s09-002", "cfg/etcd.yaml", "scenario", "COPS-E10.04-S01", "kube-bench: etcd node TLS and configuration checks"),
        ("s09-003", "cfg/controlplane.yaml", "scenario", "COPS-E10.04-S01", "kube-bench: Controller manager and scheduler validation"),
        ("s09-004", "cfg/node.yaml", "scenario", "COPS-E10.04-S01", "kube-bench: Kubelet configuration file permission audits"),
    ]

    s10_items = [
        ("s10-001", "hunting/kubelet-10250", "scenario", "COPS-E10.05-S01", "kube-hunter: Port 10250 unauthenticated kubelet command execution"),
        ("s10-002", "hunting/kubelet-readonly-10255", "scenario", "COPS-E10.05-S01", "kube-hunter: Port 10255 read-only pod specification leak"),
        ("s10-003", "hunting/proxy-exposure", "scenario", "COPS-E10.05-S01", "kube-hunter: Open kubectl proxy port 8001 exposure"),
        ("s10-004", "hunting/dashboard-access", "scenario", "COPS-E10.05-S01", "kube-hunter: Unauthenticated Kubernetes dashboard access"),
        ("s10-005", "hunting/etcd-unauth", "scenario", "COPS-E10.05-S01", "kube-hunter: Port 2379 unauthenticated etcd key-value retrieval"),
    ]

    s11_items = [
        ("s11-001", "target/k8s-cluster", "scenario", "COPS-E10.06-S01", "Trivy: Cluster-wide vulnerability and misconfiguration scanning"),
        ("s11-002", "target/k8s-misconfig", "scenario", "COPS-E10.06-S01", "Trivy: Workload spec securityContext misconfiguration check"),
        ("s11-003", "target/k8s-rbac", "scenario", "COPS-E10.08-S01", "Trivy: RBAC role granting cluster-admin or wildcard verbs"),
        ("s11-004", "target/k8s-vuln", "scenario", "COPS-E10.06-S01", "Trivy: Container image CVE scanning in live pods"),
    ]

    s12_items = [
        ("s12-001", "rbac/least-privilege", "supporting_guidance", "COPS-E10.08-GUIDE", "Kubernetes Official: Least privilege RBAC definition guidelines"),
        ("s12-002", "rbac/wildcards", "supporting_guidance", "COPS-E10.08-GUIDE", "Kubernetes Official: Eliminating wildcard API groups and resources"),
        ("s12-003", "rbac/serviceaccounts", "supporting_guidance", "COPS-E10.08-GUIDE", "Kubernetes Official: Disabling automountServiceAccountToken"),
    ]

    s13_items = [
        ("s13-001", "pss/privileged", "supporting_guidance", "COPS-E10.07-GUIDE", "Kubernetes Official: Privileged Pod Security Standard definition"),
        ("s13-002", "pss/baseline", "supporting_guidance", "COPS-E10.07-GUIDE", "Kubernetes Official: Baseline Pod Security Standard constraints"),
        ("s13-003", "pss/restricted", "supporting_guidance", "COPS-E10.07-GUIDE", "Kubernetes Official: Restricted Pod Security Standard hardening"),
    ]

    def fmt_inventory(raw_list):
        return [
            {
                "item_id": item[0],
                "path_or_section": item[1],
                "resolution": item[2],
                "target_id": item[3],
                "notes": item[4],
            }
            for item in raw_list
        ]

    sources = [
        {
            "source_id": "S01",
            "name": "command-cheatsheet",
            "category": "cheatsheet_inventory",
            "url": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c",
            "pinned_revision": "4c118399602212f205c91e8f01e418e226fa320c",
            "license": "MIT",
            "item_count": len(s01_items),
            "applicability": {
                "platforms": ["linux", "windows", "network"],
                "domains": ["reconnaissance", "web", "active_directory", "privilege_escalation"],
                "tool_maintenance": "active",
            },
            "inventory": fmt_inventory(s01_items),
        },
        {
            "source_id": "S02",
            "name": "Cheatsheet-God",
            "category": "cheatsheet_inventory",
            "url": "https://github.com/OlivierLaflamme/Cheatsheet-God/tree/b879fd62eaae297b38087b8227dde5f8f0cf7668",
            "pinned_revision": "b879fd62eaae297b38087b8227dde5f8f0cf7668",
            "license": "MIT",
            "item_count": len(s02_items),
            "applicability": {
                "platforms": ["windows", "linux", "cloud"],
                "domains": ["red_team", "active_directory", "pivoting", "web"],
                "tool_maintenance": "historical",
            },
            "inventory": fmt_inventory(s02_items),
        },
        {
            "source_id": "S03",
            "name": "Dynatrace: container misconfigurations",
            "category": "article",
            "url": "https://www.dynatrace.com/news/blog/kubernetes-security-essentials-container-misconfigurations-from-theory-to-exploitation/",
            "pinned_revision": "2026-10-02",
            "license": "Copyrighted Technical Article (fair use citation)",
            "item_count": len(s03_items),
            "applicability": {
                "platforms": ["kubernetes", "linux_containers"],
                "domains": ["container_security", "privilege_escalation"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s03_items),
        },
        {
            "source_id": "S04",
            "name": "Unit 42: modern Kubernetes threats",
            "category": "article",
            "url": "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
            "pinned_revision": "2026-10-02",
            "license": "Copyrighted Threat Research (fair use citation)",
            "item_count": len(s04_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["cloud_threats", "control_plane"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s04_items),
        },
        {
            "source_id": "S05",
            "name": "SentinelOne: Kubernetes privilege escalation",
            "category": "article",
            "url": "https://www.sentinelone.com/blog/climbing-the-ladder-kubernetes-privilege-escalation-part-1/",
            "pinned_revision": "2026-10-02",
            "license": "Copyrighted Threat Research (fair use citation)",
            "item_count": len(s05_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["privilege_escalation", "rbac"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s05_items),
        },
        {
            "source_id": "S06",
            "name": "Kubernetes RBAC privilege escalation and mitigation",
            "category": "article",
            "url": "https://seifrajhi.github.io/blog/kubernetes-rbac-privilege-escalation-mitigation/",
            "pinned_revision": "2026-10-02",
            "license": "Creative Commons Attribution 4.0",
            "item_count": len(s06_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["rbac", "privilege_escalation"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s06_items),
        },
        {
            "source_id": "S07",
            "name": "Bishop Fox: Kubernetes Bad Pods",
            "category": "article",
            "url": "https://bishopfox.com/blog/kubernetes-pod-privilege-escalation",
            "pinned_revision": "2026-10-02",
            "license": "Copyrighted Technical Research (fair use citation)",
            "item_count": len(s07_items),
            "applicability": {
                "platforms": ["kubernetes", "linux_containers"],
                "domains": ["pod_security", "node_escape"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s07_items),
        },
        {
            "source_id": "S08",
            "name": "Kubescape",
            "category": "tool_repository",
            "url": "https://github.com/kubescape/kubescape",
            "pinned_revision": "v3.0.0",
            "license": "Apache-2.0",
            "item_count": len(s08_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["compliance", "cis_benchmarks", "rbac"],
                "tool_maintenance": "active",
            },
            "inventory": fmt_inventory(s08_items),
        },
        {
            "source_id": "S09",
            "name": "kube-bench",
            "category": "tool_repository",
            "url": "https://github.com/aquasecurity/kube-bench",
            "pinned_revision": "v0.8.0",
            "license": "Apache-2.0",
            "item_count": len(s09_items),
            "applicability": {
                "platforms": ["kubernetes", "linux"],
                "domains": ["cis_benchmarks", "control_plane"],
                "tool_maintenance": "active",
            },
            "inventory": fmt_inventory(s09_items),
        },
        {
            "source_id": "S10",
            "name": "kube-hunter",
            "category": "tool_repository",
            "url": "https://github.com/aquasecurity/kube-hunter",
            "pinned_revision": "v0.6.8",
            "license": "Apache-2.0",
            "item_count": len(s10_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["cluster_hunting", "network_exposure"],
                "tool_maintenance": "active",
            },
            "inventory": fmt_inventory(s10_items),
        },
        {
            "source_id": "S11",
            "name": "Trivy Kubernetes documentation",
            "category": "tool_repository",
            "url": "https://trivy.dev/docs/latest/target/kubernetes/",
            "pinned_revision": "v0.58.0",
            "license": "Apache-2.0",
            "item_count": len(s11_items),
            "applicability": {
                "platforms": ["kubernetes", "container_images"],
                "domains": ["vulnerability_scanning", "misconfiguration"],
                "tool_maintenance": "active",
            },
            "inventory": fmt_inventory(s11_items),
        },
        {
            "source_id": "S12",
            "name": "Kubernetes RBAC good practices",
            "category": "primary_documentation",
            "url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
            "pinned_revision": "2026-10-02",
            "license": "Creative Commons Attribution 4.0",
            "item_count": len(s12_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["rbac", "governance"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s12_items),
        },
        {
            "source_id": "S13",
            "name": "Kubernetes Pod Security Standards",
            "category": "primary_documentation",
            "url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
            "pinned_revision": "2026-10-02",
            "license": "Creative Commons Attribution 4.0",
            "item_count": len(s13_items),
            "applicability": {
                "platforms": ["kubernetes"],
                "domains": ["pod_security", "admission_control"],
                "tool_maintenance": "reference_only",
            },
            "inventory": fmt_inventory(s13_items),
        },
    ]

    # fmt: on
    guidance = [
        {
            "guidance_id": "COPS-E01.01-GUIDE",
            "title": "Network discovery safety guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
        {
            "guidance_id": "COPS-E03.01-GUIDE",
            "title": "Pivoting scope guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
        {
            "guidance_id": "COPS-E06.03-GUIDE",
            "title": "Privilege boundary guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
        {
            "guidance_id": "COPS-E10.07-GUIDE",
            "title": "Pod Security Standards guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
        {
            "guidance_id": "COPS-E10.08-GUIDE",
            "title": "Kubernetes RBAC guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
        {
            "guidance_id": "COPS-E14.01-GUIDE",
            "title": "Web assessment safety guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
        {
            "guidance_id": "COPS-E17.02-GUIDE",
            "title": "Active Directory assessment guidance",
            "document_path": "docs/SUPPORTING_GUIDANCE.md",
        },
    ]

    decisions = [
        {
            "decision_id": "COPS-DECISION-REFERENCE-ONLY",
            "rationale": "Retain a source item as provenance only when COPS has no maintained, authorized scenario or supporting-guidance mapping for it.",
        }
    ]

    licensing_reviews = {
        "S01": (
            "reuse_with_attribution",
            "MIT license record: preserve required copyright and license notices when reusing eligible material.",
        ),
        "S02": (
            "reuse_with_attribution",
            "MIT license record: preserve required copyright and license notices when reusing eligible material.",
        ),
        "S03": (
            "citation_only",
            "Copyrighted technical article: retain as a citation and do not copy its procedure text.",
        ),
        "S04": (
            "citation_only",
            "Copyrighted threat research: retain as a citation and do not copy its procedure text.",
        ),
        "S05": (
            "citation_only",
            "Copyrighted technical analysis: retain as a citation and do not copy its procedure text.",
        ),
        "S06": (
            "reuse_with_attribution",
            "CC BY 4.0 record: preserve required attribution and license information for eligible reuse.",
        ),
        "S07": (
            "citation_only",
            "Copyrighted technical research: retain as a citation and do not copy its procedure text.",
        ),
        "S08": ("reuse_with_attribution", "Apache-2.0 record: preserve required notices for eligible reuse."),
        "S09": ("reuse_with_attribution", "Apache-2.0 record: preserve required notices for eligible reuse."),
        "S10": ("reuse_with_attribution", "Apache-2.0 record: preserve required notices for eligible reuse."),
        "S11": ("reuse_with_attribution", "Apache-2.0 record: preserve required notices for eligible reuse."),
        "S12": (
            "reuse_with_attribution",
            "CC BY 4.0 record: preserve required attribution and license information for eligible reuse.",
        ),
        "S13": (
            "reuse_with_attribution",
            "CC BY 4.0 record: preserve required attribution and license information for eligible reuse.",
        ),
    }

    for source in sources:
        disposition, rationale = licensing_reviews[source["source_id"]]
        source["licensing_review"] = {
            "reviewed_source_id": source["source_id"],
            "reviewed_license": source["license"],
            "disposition": disposition,
            "rationale": rationale,
        }

    provenance_doc = {
        "schema_version": "cops.provenance/v1",
        "updated_at": now_utc,
        "guidance": guidance,
        "decisions": decisions,
        "sources": sources,
    }

    # --- 4. Canonical Scenario Registry ---
    # Registering core scenarios referenced in S01-S13
    scenarios_list = [
        {
            "scenario_id": "COPS-E01.01-S01",
            "family_id": "COPS-E01.01",
            "title": "Network Port and Service Discovery",
            "description": "Performs TCP SYN and version detection against authorized IP addresses to map active listening services.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1046"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/recon/nmap.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["nmap"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target network CIDR scope authorization"],
            "owner_issue": 80,
        },
        {
            "scenario_id": "COPS-E12.02-S01",
            "family_id": "COPS-E12.02",
            "title": "Local ARP and Network Segmentation Discovery",
            "description": "Discovers active hosts on local Ethernet broadcast domains using ARP queries and verifies VLAN segmentation boundaries.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1018"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/recon/arp-scan.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["arp-scan"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target local network interface scope"],
            "owner_issue": 139,
        },
        {
            "scenario_id": "COPS-E04.01-S01",
            "family_id": "COPS-E04.01",
            "title": "Passive DNS and Certificate Transparency Enumeration",
            "description": "Queries public DNS records and certificate transparency logs to identify exposed subdomains without connecting to target infrastructure.",
            "mitre_attack": {
                "tactics": ["reconnaissance"],
                "techniques": ["T1596"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/recon/sublist3r.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux", "darwin"],
                "required_tools": ["dig", "subfinder"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "import",
            "prerequisites": ["Approved target domain names"],
            "owner_issue": 92,
        },
        {
            "scenario_id": "COPS-E04.02-S01",
            "family_id": "COPS-E04.02",
            "title": "High-Speed Active Network Boundary Discovery",
            "description": "Performs rate-limited active port discovery across perimeter IP addresses with banner capture.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1046"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/recon/masscan.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["masscan", "rustscan"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Network authorization receipt"],
            "owner_issue": 93,
        },
        {
            "scenario_id": "COPS-E04.03-S01",
            "family_id": "COPS-E04.03",
            "title": "Infrastructure RPC and Management Endpoint Evaluation",
            "description": "Interrogates RPC endpoint mappers (TCP 135) and SNMP agents (UDP 161) for system context and installed components.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1046"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/services/rpc-enum.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["rpcdump", "snmpwalk"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target host IP address"],
            "owner_issue": 94,
        },
        {
            "scenario_id": "COPS-E04.04-S01",
            "family_id": "COPS-E04.04",
            "title": "Remote Administration and SMB Share Security Audit",
            "description": "Enumerates accessible SMB shares, IPC$ null session bindings, and RDP NLA requirements on target hosts.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1135"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/services/smb-enum-shares.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["smbclient", "crackmapexec"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target host IP scope"],
            "owner_issue": 95,
        },
        {
            "scenario_id": "COPS-E04.06-S01",
            "family_id": "COPS-E04.06",
            "title": "Mail Relay and Messaging Boundary Verification",
            "description": "Verifies whether SMTP endpoints reject unauthorized open relay attempts and enforce TLS encryption.",
            "mitre_attack": {
                "tactics": ["initial-access"],
                "techniques": ["T1566"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/services/smtp-open-relay.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["swaks", "nmap"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Authorized mail gateway test scope"],
            "owner_issue": 97,
        },
        {
            "scenario_id": "COPS-E05.01-S01",
            "family_id": "COPS-E05.01",
            "title": "Web Application Inventory and Endpoint Discovery",
            "description": "Crawls web endpoints and parses OpenAPI schemas to discover exposed APIs and unauthenticated routes.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1595"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/web/ffuf.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux", "darwin"],
                "required_tools": ["ffuf"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target URL within scope"],
            "owner_issue": 100,
        },
        {
            "scenario_id": "COPS-E05.02-S01",
            "family_id": "COPS-E05.02",
            "title": "API Authentication and Token Algorithm Bypass",
            "description": "Tests JWT endpoints for algorithm none vulnerabilities and weak HMAC secret keys.",
            "mitre_attack": {
                "tactics": ["initial-access"],
                "techniques": ["T1078"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/web-vulns/jwt-none-alg.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux", "darwin"],
                "required_tools": ["python3"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Sample issued test JWT token"],
            "owner_issue": 101,
        },
        {
            "scenario_id": "COPS-E05.03-S01",
            "family_id": "COPS-E05.03",
            "title": "Structured SQL and Template Injection Boundary Testing",
            "description": "Submits harmless boundary-probing payloads (e.g. arithmetic expressions) to identify unescaped interpreter execution.",
            "mitre_attack": {
                "tactics": ["initial-access"],
                "techniques": ["T1190"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/web-vulns/sqli-blind.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["sqlmap"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Designated staging database instance"],
            "owner_issue": 102,
        },
        {
            "scenario_id": "COPS-E05.04-S01",
            "family_id": "COPS-E05.04",
            "title": "Path Traversal and Content Boundary Verification",
            "description": "Verifies that file download and display parameters strictly reject directory traversal patterns (../) and stream wrappers.",
            "mitre_attack": {
                "tactics": ["credential-access"],
                "techniques": ["T1552"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/web-vulns/lfi-path-traversal.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["curl"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target URL and parameter specification"],
            "owner_issue": 103,
        },
        {
            "scenario_id": "COPS-E05.05-S01",
            "family_id": "COPS-E05.05",
            "title": "Server-Side Request Forgery and Cloud Metadata Boundary Check",
            "description": "Verifies whether backend URL fetching parameters enforce network egress restrictions and block cloud metadata IP addresses (169.254.169.254).",
            "mitre_attack": {
                "tactics": ["credential-access"],
                "techniques": ["T1552.005"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/web-vulns/ssrf-cloud-metadata.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["curl"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Authorized HTTP listener for out-of-band detection"],
            "owner_issue": 104,
        },
        {
            "scenario_id": "COPS-E05.06-S01",
            "family_id": "COPS-E05.06",
            "title": "Cross-Origin Resource Sharing (CORS) Policy Audit",
            "description": "Evaluates Access-Control-Allow-Origin response headers against untrusted and null Origin headers.",
            "mitre_attack": {
                "tactics": ["initial-access"],
                "techniques": ["T1189"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/web-vulns/cors-misconfig.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux", "darwin"],
                "required_tools": ["curl"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target API endpoint URL"],
            "owner_issue": 105,
        },
        {
            "scenario_id": "COPS-E06.01-S01",
            "family_id": "COPS-E06.01",
            "title": "Linux Privilege Boundary and SUID Binary Audit",
            "description": "Inspects local file permissions, SUID/SGID bits, POSIX file capabilities, and sudo -l privileges for escalation vectors.",
            "mitre_attack": {
                "tactics": ["privilege-escalation"],
                "techniques": ["T1548.001"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/linux-privesc/suid-binaries.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["find", "getcap"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Local shell access on test Linux node"],
            "owner_issue": 106,
        },
        {
            "scenario_id": "COPS-E06.02-S01",
            "family_id": "COPS-E06.02",
            "title": "Windows Service and Registry Privilege Escalation Audit",
            "description": "Audits Windows service executable permissions, unquoted service paths, and AlwaysInstallElevated registry keys.",
            "mitre_attack": {
                "tactics": ["privilege-escalation"],
                "techniques": ["T1574.009"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/win-privesc/unquoted-service-path.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["windows"],
                "required_tools": ["powershell"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Authenticated Windows test endpoint"],
            "owner_issue": 107,
        },
        {
            "scenario_id": "COPS-E06.03-S01",
            "family_id": "COPS-E06.03",
            "title": "Local Host Credential Storage and File Audit",
            "description": "Scans filesystem for cleartext credentials in configuration files, bash history, and saved connection profiles.",
            "mitre_attack": {
                "tactics": ["credential-access"],
                "techniques": ["T1552.001"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/win-privesc/unattended-install.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux", "windows"],
                "required_tools": ["grep", "findstr"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["File access permissions"],
            "owner_issue": 108,
        },
        {
            "scenario_id": "COPS-E07.01-S01",
            "family_id": "COPS-E07.01",
            "title": "Active Directory Object and Relationship Analysis",
            "description": "Performs read-only LDAP enumeration to identify domain trust relationships, high-privilege groups, and delegation risks.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1087.002"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/ad/bloodhound-ingest.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux", "windows"],
                "required_tools": ["ldapsearch", "sharphound"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "import",
            "prerequisites": ["Domain authenticated read account"],
            "owner_issue": 110,
        },
        {
            "scenario_id": "COPS-E07.02-S01",
            "family_id": "COPS-E07.02",
            "title": "Kerberos Service Ticket and AS-REP Pre-Authentication Audit",
            "description": "Identifies domain accounts configured with DONT_REQ_PREAUTH (AS-REP roasting) and service principal names with weak encryption.",
            "mitre_attack": {
                "tactics": ["credential-access"],
                "techniques": ["T1558.003", "T1558.004"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/ad/kerberoast.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["impacket"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Domain account credentials reference"],
            "owner_issue": 111,
        },
        {
            "scenario_id": "COPS-E07.03-S01",
            "family_id": "COPS-E07.03",
            "title": "NTLM Relay and Multicast Poisoning Defense Verification",
            "description": "Verifies whether SMB signing, LDAP signing, and channel binding tokens are enforced to prevent NTLM credential relay.",
            "mitre_attack": {
                "tactics": ["credential-access"],
                "techniques": ["T1557.001"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/ad/ntlm-relayx.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["responder", "impacket"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Isolated test subnet"],
            "owner_issue": 112,
        },
        {
            "scenario_id": "COPS-E07.04-S01",
            "family_id": "COPS-E07.04",
            "title": "Active Directory Certificate Services (AD CS) Misconfiguration Audit",
            "description": "Audits published certificate templates for ESC1 through ESC8 vulnerabilities allowing unauthorized privilege escalation.",
            "mitre_attack": {
                "tactics": ["privilege-escalation"],
                "techniques": ["T1649"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/ad/certipy-adcs-esc1.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["certipy"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Domain account credentials reference"],
            "owner_issue": 113,
        },
        {
            "scenario_id": "COPS-E10.01-S01",
            "family_id": "COPS-E10.01",
            "title": "Kubernetes Cluster Identity and Context Verification",
            "description": "Discovers cluster endpoint, version, authentication provider, and verifies non-root worker execution boundaries.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1613"],
            },
            "provenance": {
                "source_id": "S08",
                "source_reference": "https://github.com/kubescape/kubescape",
                "version_bound": "v3.0.0",
                "license": "Apache-2.0",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["kubectl"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Kubeconfig context reference"],
            "owner_issue": 121,
        },
        {
            "scenario_id": "COPS-E10.02-S01",
            "family_id": "COPS-E10.02",
            "title": "Kubescape Automated Hardening and Control Assessment",
            "description": "Runs Kubescape compliance framework scans against cluster objects to identify NSA-CISA and CIS benchmark deviations.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1613"],
            },
            "provenance": {
                "source_id": "S08",
                "source_reference": "https://github.com/kubescape/kubescape",
                "version_bound": "v3.0.0",
                "license": "Apache-2.0",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["kubescape"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "import",
            "prerequisites": ["Cluster read-only ServiceAccount"],
            "owner_issue": 122,
        },
        {
            "scenario_id": "COPS-E10.04-S01",
            "family_id": "COPS-E10.04",
            "title": "kube-bench CIS Benchmark Control Plane Audit",
            "description": "Executes kube-bench on master and worker nodes to evaluate CIS Kubernetes Benchmark compliance.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1613"],
            },
            "provenance": {
                "source_id": "S09",
                "source_reference": "https://github.com/aquasecurity/kube-bench",
                "version_bound": "v0.8.0",
                "license": "Apache-2.0",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["kube-bench"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "import",
            "prerequisites": ["Node shell access or benchmark job spec"],
            "owner_issue": 124,
        },
        {
            "scenario_id": "COPS-E10.05-S01",
            "family_id": "COPS-E10.05",
            "title": "kube-hunter Active Vulnerability and Port Hunting",
            "description": "Probes Kubernetes clusters for open kubelet ports (10250/10255), unauthenticated etcd, and open dashboard services.",
            "mitre_attack": {
                "tactics": ["discovery"],
                "techniques": ["T1046"],
            },
            "provenance": {
                "source_id": "S10",
                "source_reference": "https://github.com/aquasecurity/kube-hunter",
                "version_bound": "v0.6.8",
                "license": "Apache-2.0",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["kube-hunter"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Target cluster IP range and worker authorization"],
            "owner_issue": 125,
        },
        {
            "scenario_id": "COPS-E10.06-S01",
            "family_id": "COPS-E10.06",
            "title": "Container Image and Cluster Workload CVE Assessment",
            "description": "Scans deployed container images and workload manifests using Trivy for known CVEs and high-severity misconfigurations.",
            "mitre_attack": {
                "tactics": ["initial-access"],
                "techniques": ["T1190"],
            },
            "provenance": {
                "source_id": "S11",
                "source_reference": "https://trivy.dev/docs/latest/target/kubernetes/",
                "version_bound": "v0.58.0",
                "license": "Apache-2.0",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["trivy"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "import",
            "prerequisites": ["Image registry or cluster read access"],
            "owner_issue": 126,
        },
        {
            "scenario_id": "COPS-E10.07-S01",
            "family_id": "COPS-E10.07",
            "title": "Kubernetes Bad Pods and Container Escape Boundary Verification",
            "description": "Evaluates container isolation against the 8 canonical Bishop Fox Bad Pods archetypes (hostPath, hostPID, hostNetwork, hostIPC, privileged, CAP_SYS_ADMIN).",
            "mitre_attack": {
                "tactics": ["privilege-escalation"],
                "techniques": ["T1611"],
            },
            "provenance": {
                "source_id": "S07",
                "source_reference": "https://bishopfox.com/blog/kubernetes-pod-privilege-escalation",
                "version_bound": "2026-10-02",
                "license": "Copyrighted Technical Research (fair use citation)",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["kubectl"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "disruptive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Disposable test namespace and worker approval"],
            "owner_issue": 127,
        },
        {
            "scenario_id": "COPS-E10.08-S01",
            "family_id": "COPS-E10.08",
            "title": "Kubernetes RBAC and Service Account Privilege Escalation Analysis",
            "description": "Analyzes RoleBindings and ClusterRoleBindings for dangerous permissions (bind, escalate, impersonate, pods/exec, secrets/get).",
            "mitre_attack": {
                "tactics": ["privilege-escalation"],
                "techniques": ["T1078.001"],
            },
            "provenance": {
                "source_id": "S06",
                "source_reference": "https://seifrajhi.github.io/blog/kubernetes-rbac-privilege-escalation-mitigation/",
                "version_bound": "2026-10-02",
                "license": "Creative Commons Attribution 4.0",
            },
            "environment": {
                "os": ["linux", "darwin"],
                "required_tools": ["kubectl"],
                "isolated_worker_required": False,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Cluster RBAC manifest export"],
            "owner_issue": 128,
        },
        {
            "scenario_id": "COPS-E10.09-S01",
            "family_id": "COPS-E10.09",
            "title": "Kubernetes Node and Control Plane Exposure Assessment",
            "description": "Scans control plane components and node Kubelet API boundaries for unauthenticated or insecurely exposed endpoints.",
            "mitre_attack": {
                "tactics": ["initial-access"],
                "techniques": ["T1190"],
            },
            "provenance": {
                "source_id": "S04",
                "source_reference": "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
                "version_bound": "2026-10-02",
                "license": "Copyrighted Threat Research (fair use citation)",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["nmap", "curl"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "read_only",
                "reversible": True,
                "safe_for_production": True,
            },
            "coverage_mode": "planned",
            "prerequisites": ["Target node IP list"],
            "owner_issue": 129,
        },
        {
            "scenario_id": "COPS-E10.10-S01",
            "family_id": "COPS-E10.10",
            "title": "Multi-Stage Kubernetes Kill-Chain Validation",
            "description": "Simulates multi-step kill chains linking compromised web workload to pod escape, service account token theft, and cluster admin escalation.",
            "mitre_attack": {
                "tactics": ["lateral-movement"],
                "techniques": ["T1611", "T1078.001"],
            },
            "provenance": {
                "source_id": "S05",
                "source_reference": "https://www.sentinelone.com/blog/climbing-the-ladder-kubernetes-privilege-escalation-part-1/",
                "version_bound": "2026-10-02",
                "license": "Copyrighted Threat Research (fair use citation)",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["kubectl", "curl"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "disruptive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Ephemeral staging cluster with full rollback automation"],
            "owner_issue": 130,
        },
        {
            "scenario_id": "COPS-E15.01-S01",
            "family_id": "COPS-E15.01",
            "title": "Controlled Adversary Payload and Command Simulation",
            "description": "Simulates controlled, reversible adversary commands in disposable containers using synthetic telemetry generators.",
            "mitre_attack": {
                "tactics": ["execution"],
                "techniques": ["T1059.004"],
            },
            "provenance": {
                "source_id": "S02",
                "source_reference": "https://github.com/OlivierLaflamme/Cheatsheet-God/tree/b879fd62eaae297b38087b8227dde5f8f0cf7668/bash-reverse-shells.txt",
                "version_bound": "b879fd6",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["bash"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Disposable worker container"],
            "owner_issue": 145,
        },
        {
            "scenario_id": "COPS-E15.02-S01",
            "family_id": "COPS-E15.02",
            "title": "Internal Network Pivoting and Tunneling Simulation",
            "description": "Verifies network segmentation and egress controls using authorized SOCKS5 proxies and TUN tunnels in a laboratory environment.",
            "mitre_attack": {
                "tactics": ["lateral-movement"],
                "techniques": ["T1090.001"],
            },
            "provenance": {
                "source_id": "S01",
                "source_reference": "https://github.com/gunyakit/command-cheatsheet/tree/4c118399602212f205c91e8f01e418e226fa320c/tunneling/chisel-socks.md",
                "version_bound": "4c11839",
                "license": "MIT",
            },
            "environment": {
                "os": ["linux"],
                "required_tools": ["chisel"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Isolated multi-tier lab network"],
            "owner_issue": 146,
        },
        {
            "scenario_id": "COPS-E15.03-S01",
            "family_id": "COPS-E15.03",
            "title": "Reversible Persistence and Defense Evasion Simulation",
            "description": "Tests host detection telemetry against Living-off-the-Land (LOLBAS) binary execution with automated cleanup verification.",
            "mitre_attack": {
                "tactics": ["defense-evasion"],
                "techniques": ["T1218"],
            },
            "provenance": {
                "source_id": "S02",
                "source_reference": "https://github.com/OlivierLaflamme/Cheatsheet-God/tree/b879fd62eaae297b38087b8227dde5f8f0cf7668/lolbas-execution.txt",
                "version_bound": "b879fd6",
                "license": "MIT",
            },
            "environment": {
                "os": ["windows", "linux"],
                "required_tools": ["powershell", "bash"],
                "isolated_worker_required": True,
            },
            "safety_profile": {
                "impact": "non_destructive",
                "reversible": True,
                "safe_for_production": False,
            },
            "coverage_mode": "laboratory",
            "prerequisites": ["Automated rollback receipt verification"],
            "owner_issue": 147,
        },
    ]

    scenarios_doc = {
        "schema_version": "cops.scenario-registry/v1",
        "updated_at": now_utc,
        "scenarios": scenarios_list,
    }

    # Write catalog files
    CATALOG.mkdir(parents=True, exist_ok=True)
    provenance_path = CATALOG / "provenance.json"
    provenance_path.write_text(json.dumps(provenance_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {provenance_path} ({len(sources)} sources, {sum(s['item_count'] for s in sources)} mapped items)")

    scenarios_path = CATALOG / "scenarios.json"
    scenarios_path.write_text(json.dumps(scenarios_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {scenarios_path} ({len(scenarios_list)} canonical scenarios registered)")


if __name__ == "__main__":
    build_registry()
