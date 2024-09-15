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
1. [Introduction](#introduction)
2. [Summary](#summary)
3. [Testing_Methodogy](#TestingMethodogy)
4. [Host_Discovery](#HostDiscovery)
5. [Sevice_Discovery_and_Port_Scanning](#SeviceDiscoveryandPortScanning)
6. [Web-Based_Attack_Surfaces](#Web-BasedAttackSurfaces)
7. [Generating_Payloads](#GeneratingPayloads)

# Introduction
This is the introduction section.

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

<p align="left">
  <img src="https://d1yjjnpx0p53s8.cloudfront.net/styles/logo-thumbnail/s3/032019/untitled-1_245.png?PZfG4BZ0MhiFothT02x6wcPjPrqeJsUK&itok=ye6EVwSc" alt="KNUST Logo" width="300"/>
</p>

The output of the nmap command includes information about hosts that are up. Tools like grep and awk are used to filter this information. To extract only the lines showing hosts that are up, you can use:

nmap -sn 10.10.10.0/24 | grep "Nmap scan report for" | awk '{print $5}'

This command sequence uses grep to find lines that indicate a host is up and also uses awk to print only the IP addresses.

To save the results to a file, redirect the output of the above command to a file. For example: 

nmap -sn 10.10.10.0/24 | grep "Nmap scan report for" | awk '{print $5}' > hosts_up.txt

This command will create (or overwrite) a file named hosts_up.txt with the list of IP addresses of hosts that are up.

You can check the contents of the file to ensure it has been written correctly by using; cat hosts_up.txt

Subdomain enumeration can also be performed using aiodnsbrute

Enumerating subdomains for https://virtualinfosecafrica.com using a wordlist located at /usr/share/wordlists/rockyou.txt. would be done by using: aiodnsbrute -d example.com -w /usr/share/wordlists/rockyou.txt










# Sevice Discovery and Port Scanning
Service discoveery or port scanning is the process of actively probing a target network to identify open ports and services running on them, essentially mapping out what applications and potential vulnerabilities are exposed on the system by checking which ports are actively listening for connections, thus providing valuable information for further penetration testing.

Service discovery and port scanning are essential components of network security assessments, penetration testing, and general network management

Knowing which services are running and which ports are open helps in assessing the security posture of a system. Unnecessary or outdated services can be exploited if not properly secured.

Certain services might have known vulnerabilities. By discovering these services, you can apply relevant security patches or configurations.

Ensuring that only authorized services are running is often a requirement for compliance with security standards and regulations.

# Web-Based Attack Surfaces
Details about the project license.

# Generating Payloads
This is the introduction section.

NOTA BENE:
- BOLDEN A TEXT.
- 
- CHANGE TEXT COLOR.
<span style="color: blue;">This is blue text.</span>




<p align="center">
  <img src="https://www.brandsoftheworld.com/logo/knust-kwame-nkrumah-university-of-science-technology?original=1" alt="KNUST Logo" width="300"/>
</p>

- IMAGES
## [![GitHub Logo](https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png)](https://github.com)
<a href="https://github.com">
  <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub Logo" width="100" height="100">
</a>

- HYPERLINK.
- 
- TABLE
- 
| One | Two | Three |
|-----|-----|-------|
| one | two | three |



| DDoS-ICMP_Flood     | DDoS-RSTFIN_Flood         | DDoS-HTTP_Flood       |
|---------------------|---------------------------|-----------------------|
| DDoS-UDP_Flood      | DDoS-SynonymousIP_Flood    | DDoS-SlowLoris        |
| DDoS-TCP_Flood      | DDoS-PSHACK_Flood          | DDoS-ICMP_Fragmentation|
| DDoS-SYN_Flood      | DDoS-ACK_Fragmentation     | DDoS-PSHACK_Flood      |





![My Image](https://github.com/your-username/your-repo-name/blob/main/images/my-image.png)
