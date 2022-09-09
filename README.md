# h4k-sore
*A Collection of Pentesting Tools and Resources.*

![hackerman](https://i.kym-cdn.com/editorials/icons/mobile/000/001/508/hackerman-icon.jpg)

# Index
1. [CTF Resources](#ctf-and-skill-development)
2. [News](#news-and-info)
3. [Pentesting Resources](#pentesting-resources)
4. [Reversing Resources](#reversing)
5. [Malware Analysis](#malware-analysis)
6. [Anonymisers](#anonymisers)
7. [Honeypots](#honeypots)
8. [Network Defence](#network-perimeter-defense)
9. [Operating Systems](#security-and-pentesting-operating-systems)
10. [Other Collections](#other-cybersecurity-collections)
11. [References](#references)

# CTF and Skill Development

## CTF sites
- [PicoCTF](https://picoctf.com)
- [TryHackMe](https://tryhackme.com)
- [HackTheBox](https://hackthebox.eu)
- [Google CTF](https://capturetheflag.withgoogle.com/)
- [VulnHub](https://www.vulnhub.com/)
- [Defend the Web](https://defendtheweb.net/)

## CTF Resources
- [CTF Field Guide](https://trailofbits.github.io/ctf/) - CTF Field Guide repository.

## CTF Tools
- [AutoSploit](https://github.com/NullArray/AutoSploit) - Automated mass exploiter.

## Reversing
- [Micro Corruption](https://microcorruption.com) - Reverse Engineering playground.

# News and Info

- [Ouch! - Sans](https://www.sans.org/newsletters/ouch/?msc=main-nav)
- [Dark Reading](https://www.darkreading.com/) - Community for security professionals.
- [Krebs on Security](https://krebsonsecurity.com/) - In depth analysis and information.
- [OWASP](https://owasp.slack.com/) - Essential community for Cybsec professionals.
- [Decentralize](https://decentralize.today/) - Updates on privacy, decentralization and related issues.

# Pentesting Resources

## Exploit Information and Resources
- [Privilege Escalation](https://github.com/Ignitetechnologies/Privilege-Escalation) - Excellent Github repository.
- [Active Directory Exploitation](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) - Great AD cheatsheet.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Pentesters best friend.
- [Exploit Databse](https://www.exploit-db.com/) - Maintained by Offensive Security. 
- [NMAP: Hackertarget Reference Guide](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/) - Decent Nmap cheatsheet.
- [The Pentesters Framework](https://github.com/trustedsec/ptf) - Distro organized around the Penetration Testing Execution Standard (PTES) [^2]


## Web Tools
- [BurpSuite](https://portswigger.net/burp) - A graphical tool to testing website security.
- [Commix](https://github.com/commixproject/commix) - Automated All-in-One OS Command Injection and Exploitation Tool.
- [Hackbar](https://addons.mozilla.org/en-US/firefox/addon/hackbartool/) - Firefox addon for easy web exploitation.
- [CyberChef](https://gchq.github.io/CyberChef) - Web app for data analysis; great for CTFs.

## Pentesting Tools
- [Metasploit](https://github.com/rapid7/metasploit-framework) - Easy to use, all-in-one exploit kit.
- [Low Orbital Ion Cannon](https://github.com/NewEraCracker/LOIC) - Open Source Network stress tool (DDoS) 

## Scripts
- [CTF Tools](https://github.com/zardus/ctf-tools) - Setup scripts to install various security research tools.

# Reversing

- [Reverse Engineering Cheatsheet](https://www.cybrary.it/wp-content/uploads/2017/11/cheat-sheet-reverse-v6.png)
- [BeginRE](https://www.begin.re/the-workshop) - Reverse Engineering workshop.

## RE Tools
- [radare2](https://github.com/radare/radare2) - RE toolkit and cutter.
- [IDA](https://www.hex-rays.com/products/ida/) - Disassembly and Debugging Toolkit.
- [Ghidra](https://ghidra-sre.org/) - Toolkit developed by the NSA.

# Malware Analysis

## Information Aquisition
- [VirusTotal](https://www.virustotal.com/gui/) - Online malware analysis tool.
- [Any.Run](https://any.run/) - Online Malware Analysis.
- [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) - Comprehensive analysis repository.
- [Malzilla](http://malzilla.sourceforge.net/) - Malware hunting tool.
- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - AlienVault Open Threat Exchange (OTX).


## Forensic Tools
- [USBRip](https://github.com/snovvcrash/usbrip) - Track USB events on GNU/Linux.
- [Volatility](https://github.com/volatilityfoundation/volatility) - Open Source memory dump investigation toolset.
- [Wireshark](https://www.wireshark.org) - Used to analyze pcap.
- [Sleuthkit](https://github.com/sleuthkit/sleuthkit) - CLI tools for forensic investigation.
- [Autopsy](http://www.sleuthkit.org/autopsy/) - GUI for the Sleuthkit.

## Sandboxes
_Play with danger_
- [Cuckoo](https://cuckoosandbox.org/) - Malware analysis sandbox [^1]
  - [Cuckoo Repository](https://github.com/cuckoosandbox/cuckoo) 
- [MalwareLab VM](https://github.com/f0wl/MalwareLab_VM-Setup) - Collection of setup scripts
- [ThreatPursuit](https://github.com/mandiant/ThreatPursuit-VM) - Mandiant Threat Intelligence VM [^1]
- [Firejail](https://firejail.wordpress.com/) - Sandbox your apps on Linux [^1]
- [Flare VM](https://github.com/fireeye/flare-vm/) - Windows based MA distribution. [^1]

# Anonymisers
_Conceal your identity_
- [Privoxy](http://www.privoxy.org/) - An open source proxy server with some privacy features. [^1]
- [Tor](https://www.torproject.org/) - The Onion Router, for browsing the web without leaving traces of the client IP.
- [Mullvad](https://mullvad.net/en/) - Highly Anonoymous VPN. Cash, Monero and Bitcoin accepted.
- [I2P](https://geti2p.net/) - Invisible Internet Project.
 
  
# Honeypots
_Treats too good to resist_
- [Honeyd](http://www.honeyd.org/) - Virtual honeynet. 
- [CanaryTokens](https://github.com/thinkst/canarytokens) - Self-hostable honeytoken generator and reporting dashboard; demo version available at [CanaryTokens.org](https://canarytokens.org/).
- [Kushtaka](https://kushtaka.org) - Sustainable all-in-one honeypot and honeytoken orchestrator for under-resourced blue teams.
- [Manuka](https://github.com/spaceraccoon/manuka) - Open-sources intelligence (OSINT) honeypot that monitors reconnaissance attempts by threat actors and generates actionable intelligence for Blue Teamers.

# Network Perimeter Defense

- [Gatekeeper](https://github.com/AltraMayor/gatekeeper) - First open source Distributed Denial of Service (DDoS) protection system. [^1]
- [fwknop](https://www.cipherdyne.org/fwknop/) - Protects ports via Single Packet Authorization in your firewall. [^1]
- [ssh-audit](https://github.com/jtesta/ssh-audit) - Simple tool that makes quick recommendations for improving an SSH server's security posture. [^1]

## Detection
- [Snort](https://snort.org/) - Widely-deployed, Free Software IPS capable of real-time packet analysis, traffic logging, and custom rule-based triggers.
- [Suricata](https://suricata-ids.org/) - Free, cross-platform, IDS/IPS.
- [Wireshark](https://www.wireshark.org) - The free and open-source packet analyzer

# Security and Pentesting Operating Systems

- [BackBox](https://backbox.org/) - Ubuntu based OS.
- [BlackArch Linux](https://blackarch.org/) - Arch Linux pentesting distribution.
- [Fedora Security Lab](https://labs.fedoraproject.org/security/) - Based on Fedora.
- [Kali Linux](https://www.kali.org/) - Well known pentesting OS.
- [Parrot Security OS](https://www.parrotsec.org/) - Standard security and pentesting OS, used by HackTheBox.
- [Pentoo](http://www.pentoo.ch/) - Based on Gentoo.

# Other Cybersecurity Collections

# References
[^1]: Awesome Cybersecurity Blueteam https://github.com/fabacab/awesome-cybersecurity-blueteam
[^2]: Awesome Pentest https://github.com/enaqx/awesome-pentest

