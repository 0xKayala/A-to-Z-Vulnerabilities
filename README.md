# A-to-Z-Vulnerabilities [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> This is a Kind of Dictionary that contains all kinds of Vulnerabilities and security concepts of Web Applications, Mobile Applications and Network Architectures in Alphabetical Order.

## Contents

- [Injection Vulnerabilities](#Injection-Vulnerabilities)
    - [1. SQL Injection](#SQL-Injection)
        - [1.1 In-band SQL Injection](#In-band-SQL-Injection)
            - [Error-based SQL Injection](#Error-based-SQL-Injection)
            - [Union-based SQL Injection](#Union-based-SQL-Injection)
        - [1.2 Blind SQL Injection](#Blind-SQL-Injection)
            - [Boolean SQL Injection](#Boolean-SQL-Injection)
            - [Time-based SQL Injection](#Time-based-SQL-Injection)
        - [1.3 Out-of-band SQLi](#Out-of-band-SQLi)
    - [2. Cross-Site Scripting](#Cross-Site-Scripting)
        - [2.1 Reflected Cross-Site Scripting](#Reflected-Cross-Site-Scripting)
        - [2.2 Stored Cross-Site Scripting](#Stored-Cross-Site-Scripting)
        - [2.3 DOM Cross-Site Scripting](#DOM-Cross-Site-Scripting)
    - [3. Cross-Site Request Forgery](#Cross-site-Request-Forgery)
    - [4. Remote Code Execution](#Remote-Code-Execution)
    - [5. Command Injection](#Command-Injection)
    - [6. XML Injection](#XML-Injection)
    - [7. LDAP Injection](#LDAP-Injection)
    - [8. XPath Injection](#XPath-Injection)
    - [9. HTML Injection](#HTML-Injection)
    - [10. Server-Side Includes Injection](#Server-Side-Includes-Injection)
    - [11. OS Command Injection](#OS-Command-Injection)
    - [13. Server-Side Template Injection](#Server-Side-Template-Injection)

- [Broken Authentication and Session Management](#Broken-Authentication-and-Session-Management)
    - [14. Session Fixation](#Session-Fixation)
    - [15. Brute Force Attack](#Brute-Force-Attack)
    - [16. Session Hijacking](#Session-Hijacking)
    - [17. Password Cracking](#Password-Cracking)
    - [18. Weak Password Storage](#Weak-Password-Storage)
    - [19. Insecure Authentication](#Insecure-Authentication)
    - [20. Cookie Theft](#Cookie-Theft)
    - [21. Credential Reuse](#Credential-Reuse)

- [Sensitive Data Exposure](#Sensitive-Data-Exposure)
    - [22. Inadequate Encryption](#Inadequate-Encryption)
    - [23. Insecure Direct Object References](#IDOR)
    - [24. Data Leakage](#Data-Leakage)
    - [25. Unencrypted Data Storage](#Unencrypted-Data-Storage)
    - [26. Missing Security Headers](#Missing-Security-Headers)
    - [27. Insecure File Handling](#Insecure-File-Handling)

- [Security Misconfiguration](#Security-Misconfiguration)
    - [28. Default Passwords](#Default-Passwords)
    - [29. Directory Listing](#Directory-Listing)
    - [30. Unprotected API Endpoints](#Unprotected-API-Endpoints)
    - [31. Open Ports and Services](#Open-Ports-and-Services)
    - [32. Improper Access Controls](#Improper-Access-Controls)
    - [33. Information Disclosure](#Information-Disclosure)
    - [34. Unpatched Software](#Unpatched-Software)
    - [35. Misconfigured CORS](#Misconfigured-CORS)
    - [36. HTTP Security Headers Misconfiguration](#HTTP-Security-Headers-Misconfiguration)

- [XML-Related Vulnerabilities](#XML-Related-Vulnerabilities)
    - [37. XML External Entity Injection](#XML-External-Entity-Injection)
    - [38. XML Entity Expansion](#XML-Entity-Expansion)
    - [39. XML Bomb](#XML-Bomb)

- [Broken Access Control](#Broken-Access-Control)
    - [40. Inadequate Authorization](#Inadequate-Authorization)
    - [41. Privilege Escalation](#Privilege-Escalation)
    - [42. Insecure Direct Object References](#Insecure-Direct-Object-References)
    - [43. Forceful Browsing](#Forceful-Browsing)
    - [44. Missing Function-Level Access Control](#Missing-Function-Level-Access-Control)

- [Insecure Deserialization](#Insecure-Deserialization)
    - [45. Remote Code Execution via Deserialization](#Remote-Code-Execution-via-Deserialization)
    - [46. Data Tampering](#Data-Tampering)
    - [47. Object Injection](#Object-Injection)

- [API Security Issues](#API-Security-Issues)
    - [48. Insecure API Endpoints](#Insecure-API-Endpoints)
    - [49. API Key Exposure](#API-Key-Exposure)
    - [50. Lack of Rate Limiting](#Lack-of-Rate-Limiting)
    - [51. Inadequate Input Validation](#Inadequate-Input-Validation)

- [Insecure Communication](#Insecure-Communication)
    - [52. Man-in-the-Middle Attack](#Man-in-the-Middle-Attack)
    - [53. Insufficient Transport Layer Security](#Insufficient-Transport-Layer-Security)
    - [54. Insecure SSL/TLS Configuration](#Insecure-SSL/TLS-Configuration)
    - [55. Insecure Communication Protocols](#Insecure-Communication-Protocols)

- [Client-Side Vulnerabilities](#Client-Side-Vulnerabilities)
    - [56. DOM Cross-Site Scripting](#DOM-Cross-Site-Scripting)
    - [57. Insecure Cross-Origin Communication](#Insecure-Cross-Origin-Communication)
    - [58. Browser Cache Poisoning](#Browser-Cache-Poisoning)
    - [59. Clickjacking](#Clickjacking)
    - [60. HTML5 Security Issues](#HTML5-Security-Issues)

- [Denial of Service](#Denial-of-Service)
    - [61. Distributed Denial of Service](#Distributed-Denial-of-Service)
    - [62. Application Layer DoS](#Application-Layer-DoS)
    - [63. Resource Exhaustion](#Resource-Exhaustion)
    - [64. Slowloris Attack](#Slowloris-Attack)
    - [65. XML Denial of Service](#XML-Denial-of-Service)

- [Other Web Vulnerabilities](#Other-Web-Vulnerabilities)
    - [66. Server-Side Request Forgery](#Server-Side-Request-Forgery)
    - [67. HTTP Parameter Pollution](#HTTP-Parameter-Pollution)
    - [68. Insecure Redirects and Forwards](#Insecure-Redirects-and-Forwards)
    - [69. File Inclusion Vulnerabilities](#File-Inclusion-Vulnerabilities)
        - [Local File Inclusion](#Local-File-Inclusion)
        - [Remote File Inclusion](#Remote-File-Inclusion)
    - [70. Security Header Bypass](#Security-Header-Bypass)
    - [71. Missing Security Response Headers](#missing-security-response-headers)
    - [72. Clickjacking](#Clickjacking)
    - [73. Inadequate Session Timeout](#Inadequate-Session-Timeout)
    - [74. Insufficient Logging and Monitoring](#Insufficient-Logging-and-Monitoring)
    - [75. Business Logic Vulnerabilities](#Business-Logic-Vulnerabilities)
    - [76. API Abuse](#API-Abuse)

- [Mobile Web Vulnerabilities](#Mobile-Web-Vulnerabilities)
    - [77. Insecure Data Storage on Mobile Devices](#Insecure-Data-Storage-on-Mobile-Devices)
    - [78. Insecure Data Transmission on Mobile Devices](#Insecure-Data-Transmission-on-Mobile-Devices)
    - [79. Insecure Mobile API Endpoints](#Insecure-Mobile-API-Endpoints)
    - [80. Mobile App Reverse Engineering](#Mobile-App-Reverse-Engineering)

- [IoT Web Vulnerabilities](#IoT-Web-Vulnerabilities)
    - [81. Insecure IoT Device Management](#Insecure-IoT-Device-Management)
    - [82. Weak Authentication on IoT Devices](#Weak-Authentication-on-IoT-Devices)
    - [83. IoT Device Vulnerabilities](#IoT-Device-Vulnerabilities)

- [Web of Things (WoT) Vulnerabilities](#Web-of-Things-(WoT)-Vulnerabilities)
    - [84. Unauthorized Access to Smart Homes](#Unauthorized-Access-to-Smart-Homes)
    - [85. IoT Data Privacy Issues](#IoT-Data-Privacy-Issues)

- [Authentication Bypass](#Authentication-Bypass)
    - [86. Insecure "Remember Me" Functionality](#Insecure-"Remember-Me"-Functionality)
    - [87. CAPTCHA Bypass](#CAPTCHA-Bypass)

- [Server-Side Request Forgery](#Server-Side-Request-Forgery)
    - [88. Blind Server-Side Request Forgery](#Blind-Server-Side-Request-Forgery)
    - [88. Time-Based Blind Server-Side Request Forgery](#Time-Based-Blind-Server-Side-Request-Forgery)

- [Content Spoofing](#Content-Spoofing)
    - [89. MIME Sniffing](#MIME-Sniffing)
    - [90. X-Content-Type-Options Bypass](#X-Content-Type-Options-Bypass)
    - [91. Content Security Policy Bypass](#Content-Security-Policy-Bypass)

- [Business Logic Flaws](#Business-Logic-Flaws)
    - [92. Inconsistent Validation](#Inconsistent-Validation)
    - [93. Race Conditions](#Race-Conditions)
    - [94. Order Processing Vulnerabilities](#Order-Processing-Vulnerabilities)
    - [95. Price Manipulation](#Price-Manipulation)
    - [96. Account Enumeration](#Account-Enumeration)
    - [97. User-Based Flaws](#User-Based-Flaws)

- [Zero-Day Vulnerabilities](#Zero-Day-Vulnerabilities)
    - [98. Unknown Vulnerabilities](#Unknown-Vulnerabilities)
    - [99. Unpatched Vulnerabilities](#Unpatched-Vulnerabilities)
    - [100. Day-Zero Exploits](#Day-Zero-Exploits)
 
- [Network Security Vulnerabilities](#Network-Security-Vulnerabilities)
    - [DNS Zone Transfer](#DNS-Zone-Transfer)
    - [LDAP Anonymous Login](#LDAP-Anonymous-Login)
    - [Remote Code Execution on SMB 3.1.1](#Remote-Code-Execution-on-SMB-3.1.1)
    - [SMB Work Group Enumeration with Anonymous login](#SMB-Work-Group-Enumeration-with-Anonymous-login)
- [Cross-Origin Resource Sharing](#Cross-Origin-Resource-Sharing)
- [Cryptographic Failures](#Cryptographic-Failures)
- [Code Injection](#Code-Injection)
- [Command injection](#Command-injection)
- [Directory traversal or Path Traversal](#Directory-traversal-or-Path-Traversal)
- [Forced browsing](#Forced-browsing)
- [HTTP Request Smuggling](#HTTP-Request-Smuggling)
- [HTTP Headers](#HTTP-Headers)
    - [HTTP Request Header](#HTTP-Request-Header)
    - [HTTP Response Header](#HTTP-Response-Header)
- [Insecure Design](#Insecure-Design)
- [Identification and Authentication Failures](#Identification-and-Authentication-Failures)
- [Nmap Vulnerability Scanner](#Nmap-Vulnerability-Scanner)
- [Security Misconfiguration](#Security-Misconfiguration)
- [Software and Data Integrity Failures](#Software-and-Data-Integrity-Failures)
- [Security Logging and Monitoring Failures](#Security-Logging-and-Monitoring-Failures)
- [Vulnerable and Outdated components](#Vulnerable-and-Outdated-components)


---

## Authentication Bypass

An attacker gains access to application, service, or device with the privileges of an authorized or privileged user by evading or circumventing an authentication mechanism. The attacker is therefore able to access protected data without authentication ever having taken place. This refers to an attacker gaining access equivalent to an authenticated user without ever going through an authentication procedure. This is usually the result of the attacker using an unexpected access procedure that does not go through the proper checkpoints where authentication should occur. For example, a web site might assume that all users will click through a given link in order to get to secure material and simply authenticate everyone that clicks the link. However, an attacker might be able to reach secured web content by explicitly entering the path to the content rather than clicking through the authentication link, thereby avoiding the check entirely. This attack pattern differs from other authentication attacks in that attacks of this pattern avoid authentication entirely, rather than faking authentication by exploiting flaws or by stealing credentials from legitimate users.

Mitigation:
1) Do not rely on client side only make the checks at the server side.
2) Verifying the client side and taking decisions is very very dangerous.
3) Use authentication based on strong tokens such as json web token mechanism.
4) Use authentication based on encrypted data which can be AES for example.

Image Credits: https://www.bugcrowd.com/blog/authentication-bypass/

![image](https://user-images.githubusercontent.com/16838353/196902854-dece27e7-5d44-40ca-9bb7-36441d8f8932.png)

## Broken Access Control

Broken acess control is flaw in web application which is occur due to "poor implementation" of access control mechanism that can be easily exploited. This flaw allow attacker/unauthorised user to access the contents that they are not allowed to view, can perform unauthorised functions, even an attacker can delete the content, or take over site administration. There are many vulnerabilities which contribute to this risk, For instance, if the developer forgets to validate permissions when dealing with identifiers, the application becomes vulnerable to Insecure Direct Object Reference (IDOR). Other vulnerabilities include Cross-site Request Forgery (CSRF), Cross-Origin Resource Sharing (CORS) misconfigurations, directory traversal and forced browsing

Mitigation:
1) Proper implementations of access control to the users.
2) Delete any inactive or unnecessary accounts.
3) Shutdown unnecessary service and access point.
4) Use multi-factor authentication at all access points
5) Disable web server directory listing

Image Credits: https://www.geeksforgeeks.org/

![BAC](https://user-images.githubusercontent.com/16838353/196788103-8f86536d-cd1b-41b2-9777-2e0d88e3e4d3.png)

## Business Logic Flaws

Business logic vulnerabilities are flaws in the design and implementation of an application that allows an attacker to elicit unintended behaviour.
This potentially enables attackers to manipulate legitimate functionality to achieve a malicious goal.

## Cross-Site Scripting

XSS is a client-side code injection where the attacker tries to inject a malicious script into a trusted site. This script is in the form of JavaScript code, which can redirect a victim from their legitimate site to an attacker site without their knowledge. This weakness in an application allows an attacker to steal cookies, steal user sessions, and thereby gain illegitimate access to the system.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196904106-1633ecc9-3076-464b-aabd-ad6d6400c90b.png)

### Reflected Cross-Site Scripting

Reflected XSS attack occurs when a malicious script is reflected in the website’s results or response.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![rxss](https://user-images.githubusercontent.com/16838353/196875177-70fe8797-2526-41f3-b457-379a3711486d.png)

### Stored Cross-Site Scripting

The malicious data is stored permanently on a database and is later accessed and run by the victims without knowing the attack

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

<img width="1743" alt="stored-xss" src="https://user-images.githubusercontent.com/16838353/196875328-0ca9bfad-faa9-4e57-9fe8-0bd54f9b89c6.png">

### DOM Cross-Site Scripting

DOM Based XSS wherein the attacker’s payload is executed due to modifying the DOM “environment” in the victim’s browser used by the original client-side script. The client-side code runs in an “unexpected” manner

Image Credits: https://medium.com/iocscan/dom-based-cross-site-scripting-dom-xss-3396453364fd

![image](https://user-images.githubusercontent.com/16838353/196901948-7cb86a34-7536-423e-862f-df7c94a39cb6.png)

## Cross-site Request Forgery

Cross-site Request Forgery (CSRF) - is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. Using CSRF, a hacker can forge a request from a legitimate website to the unsuspecting logged in user. By sending this forged link via email or chat, an attacker can trick the users of a web application into executing actions of the attacker’s choosing

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![CSRF](https://user-images.githubusercontent.com/16838353/196786974-d30c9660-7453-4b0f-bca0-897c21a1ebe6.jpg)

## Cross-Origin Resource Sharing (CORS)

Cross-Origin Resource Sharing (CORS) - is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP). However, it also provides potential for cross-domain attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as cross-site request forgery (CSRF)

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![cors](https://user-images.githubusercontent.com/16838353/196784777-b5ab1c7a-46e9-465f-82c9-4749617dfdd6.png)

## Same-origin policy (SOP)

The same-origin policy is a web browser security mechanism that aims to prevent websites from attacking each other.

The same-origin policy restricts scripts on one origin from accessing data from another origin. An origin consists of a URI scheme, domain and port number. For example, consider the following URL:

`http://normal-website.com/example/example.html`

This uses the scheme `http`, the domain `normal-website.com`, and the port number `80`. The following table shows how the same-origin policy will be applied if the content at the above URL tries to access other origins:

<table>
<thead>
<tr>
<th><strong>URL accessed</strong></th>
<th><strong>Access permitted?</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><code>http://normal-website.com/example/</code></td>
<td>Yes: same scheme, domain, and port</td>
</tr>

## Cryptographic Failures

A cryptographic failure is a critical web application security vulnerability that exposes sensitive application data on a weak or non-existent cryptographic algorithm. These can be passwords, patient health records, business secrets, credit card information, email addresses, or other personal user information. Apart from exposing sensitive information, as cryptographic failures can also compromise systems, the implications of this vulnerability are considered one of the most critical security risks for both organizations and business users

## Code Injection

Code injection is one of the most common types of injection attacks. If attackers know the programming language, the framework, the database or the operating system used by a web application, they can inject code via text input fields to force the webserver to do what they want. These types of injection attacks are possible on applications that lack input data validation. If a text input field lets users enter whatever they want, then the application is potentially exploitable. To prevent these attacks, the application needs to restrict as much as it can the input users are allowed to enter. For example, it needs to limit the amount of expected data, to check the data format before accepting it, and to restrict the set of allowed characters.

## Command injection

Sometimes web applications need to call a system command on the webserver that is running them. In such instances, if user input is not validated and restricted, a command injection can occur. Unlike code injections, command injections only require the attacker to know the operating system used. Then, the attacker inserts a command into the system, using the user privileges. The inserted command then executes in the host system. A command injection can compromise that application, its data, the entire system, connected servers, systems, and other infrastructure.

#### Tools:
- [commix](https://github.com/commixproject/commix) - Automated All-in-One OS command injection and exploitation tool.

Source: https://security-flashcards.com |
Image Credits: https://twitter.com/secflashcards

![image](https://user-images.githubusercontent.com/16838353/200125875-01abbfd4-626f-46aa-988e-47ee7cf467dd.png)

## Directory traversal or Path Traversal

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

## DNS Zone Transfer

DNS Zone Transfer vulnerability, also known as "AXFR (AXIS Forwarding)" vulnerability, is a security weakness that allows unauthorized parties to obtain a complete copy of the DNS zone data from a primary DNS server. This can lead to potential exposure of sensitive information about the domain, such as hostnames, IP addresses, and other DNS records.

The DNS (Domain Name System) protocol uses a hierarchical system of distributed DNS servers to translate human-readable domain names (e.g., example.com) into IP addresses (e.g., 192.168.0.1) used by computers to locate resources on the internet. DNS servers are categorized into primary and secondary servers. The primary DNS server holds the authoritative copy of the DNS zone for a domain, while secondary DNS servers maintain a replica of the zone for redundancy and improved query performance.

The DNS Zone Transfer vulnerability occurs when the primary DNS server is improperly configured to allow zone transfers to any requesting server, rather than limiting access to authorized secondary DNS servers. This misconfiguration can be exploited by attackers using tools like nslookup or other DNS querying tools to request the entire DNS zone data. If the server allows the transfer, the attacker gains access to sensitive information that could be used for reconnaissance or targeted attacks.

Example Commands to check for DNS Zone Transfer:
1. `nslookup -type=any IP`
2. `dig axfr @IP`

## File Inclusion

The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a “dynamic file inclusion” mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.
This can lead to something as outputting the contents of the file, but depending on the severity, it can also lead to:

1) Code execution on the web server
2) Code execution on the client-side such as JavaScript which can lead to other attacks such as cross-site scripting (XSS)
3) Denial of Service (DoS)
4) Sensitive Information Disclosure

### Local File Inclusion

Local file inclusion (also known as LFI) is the process of including files, that are already locally present on the server, through the exploiting of vulnerable inclusion procedures implemented in the application. This vulnerability occurs, for example, when a page receives, as input, the path to the file that has to be included and this input is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash) to be injected. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196878293-039d7eff-0334-403d-a899-7a0395948012.png)

### Remote File Inclusion

Remote File Inclusion (also known as RFI) is the process of including remote files through the exploiting of vulnerable inclusion procedures implemented in the application. This vulnerability occurs, for example, when a page receives, as input, the path to the file that has to be included and this input is not properly sanitized, allowing external URL to be injected. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196878480-c8796673-9fd8-4d4c-89b0-2aa67411cfa4.png)

## Forced browsing

A Forced browsing attack is a vulnerability in which an unauthorized user has access to the contents of an authorized user. Forced browsing is an attack when a Web application has more than one user privilege level for the same user. Thus, an attacker gets sensitive information which should otherwise not be accessible to him/her.The attacker can use a brute force approach to get common directories, files, or information of user accounts present on the website.

## HTTP Parameter Pollution

HTTP Parameter Pollution (HPP) is a Web attack evasion technique that allows an attacker to craft a HTTP request in order to manipulate or retrieve hidden information. This evasion technique is based on splitting an attack vector between multiple instances of a parameter with the same name. Since none of the relevant HTTP RFCs define the semantics of HTTP parameter manipulation, each web application delivery platform may deal with it differently. In particular, some environments process such requests by concatenating the values taken from all instances of a parameter name within the request. This behavior is abused by the attacker in order to bypass pattern-based security mechanisms.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196890388-0655f895-c585-4ca8-9a0c-60828aa5474b.png)

## HTTP Request Smuggling

HTTP request smuggling exploits the inconsistency in parsing non-RFC-compliant HTTP requests via two HTTP devices (generally a backend server and HTTP-enabled firewall or a front-end proxy). The HTTP request smuggling process is carried out by creating multiple, customized HTTP requests that make two target entities see two distinct series of requests.
The HTTP header offers two distinct ways of specifying where the request ends: the Transfer-Encoding header and the Content-Length header. An HTTP request smuggling vulnerability occurs when an attacker sends both headers in a single request. This can cause either the front-end or the back-end server to incorrectly interpret the request, passing through a malicious HTTP query.
Request smuggling vulnerabilities let cybercriminals side-step security measures, attain access to sensitive information, and directly compromise various application users. It can also be used for secondary exploits, including bypassing firewalls, partial cache poisoning, and cross-site scripting (XSS).

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196884498-54299b49-eb10-43bc-a4c2-5bdff4ae5bd5.png)

## HTTP Headers

The HTTP headers are used to pass additional information between the clients and the server through the request and response header. All the headers are case-insensitive, headers fields are separated by colon, key-value pairs in clear-text string format. The end of the header section denoted by an empty field header. There are a few header fields that can contain the comments. And a few headers can contain quality(q) key-value pairs that separated by an equal sign.

### HTTP Request Header

This type of headers contains information about the fetched request by the client.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196882019-32e30ad1-a3cc-4813-ba02-314503c5bb4b.png)

### HTTP Response Header

This type of headers contains the location of the source that has been requested by the client.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196883328-5047f9dd-3fcc-48f8-aff7-dad27e20ec86.png)

## Injection

During an injection attack, an attacker can provide malicious input to a web application (inject it) and change the operation of the application by forcing it to execute certain commands. An injection attack can expose or damage data and lead to a denial of service or a full web server compromise. Such attacks are possible due to vulnerabilities in the code of an application that allows for unvalidated user input. Injection attacks are one of the most common and dangerous web attacks. Injection vulnerability is ranked #1 in the OWASP Top Ten Web Application Security Risks. Several injection attacks are also featured in the Common Weakness Enumeration (CWE)

## Insecure Direct Object Reference

Insecure Direct Object Reference (IDOR) - This vulnerability happens when the application doesn’t properly validate access to resources through IDs. For example, an application shows a purchase order to the customer using the /orders/1234 endpoint. However, the user whose order id is 1234 can also access other orders by simply changing the order id. This is the simplest scenario, but there are many other techniques to exploit an IDOR vulnerability

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![idor](https://user-images.githubusercontent.com/16838353/196786238-4f9b3874-c0bf-413f-972d-eb8c688fb013.jpg)

## Insecure Design

Insecure design is focused on the risks associated with flaws in design and architecture. It focuses on the need for threat modeling, secure design patterns, and principles. The flaws in insecure design are not something that can be rectified by an implementation. OWASP differentiates insecure design from security implementation and controls as follows: An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks. To exploit insecure design, attackers can threat model workflows in the software to reveal a broad range of vulnerabilities and weaknesses.
Example:
1) Attacker exploits a poorly designed API that does not properly filter input.
2) The attacker scans for vulnerable APIs and identifies an API that does not properly filter input and does not use the organizations API security gateway.
3) The attacker injects a malicious script into the vulnerable API.
4) The victim's browser accesses the API through the application.
5) The browser loads content with the malicious script.

## Identification and Authentication Failures

Identification and authentication failures can occur when functions related to a user's identity, authentication, or session management are not implemented correctly or not adequately protected by an application. Attackers may be able to exploit identification and authentication failures by compromising passwords, keys, session tokens, or exploit other implementation flaws to assume other users' identities, either temporarily or permanently.
Attackers use a range of techniques to exploit broken authentication such as:
1) Brute force/credential stuffing
2) Session hijacking
3) Session fixation
4) Cross-Site Request Forgery (CSRF)
5) Execution After Redirect (EAR)
6) One-click attack

## LDAP Anonymous Login

If we are able to establish a connection to the LDAP service with anonymous credentials then it is considered as an "LDAP Anonymous Login". Allowing anonymous access to an LDAP server can potentially expose sensitive information, such as user account details and organizational structure, to unauthorized users or attackers. We can also enumerate some server-related information with a basic NSE script.

Attackers can use this information for reconnaissance purposes, to identify potential targets and weaknesses in the system, and even launch more sophisticated attacks such as privilege escalation, lateral movement, or data exfiltration.

Therefore, it is generally recommended to disable anonymous access to LDAP servers and require authentications for all connections. This can be achieved by configuring proper access controls, authentication policies, and secure communications protocols such as SSL/TLS.

Command to check for "LDAP Anonymous Login":
1. `nmap -n -sV --script "ldap* and not brute" IP`

## Nmap Vulnerability Scanner

The Nmap vulnerability scanner (also known as “Network Mapper”) is a popular, open-source tool for security auditing and related network discovery. Authorized users can utilize Nmap to identify the devices running on their systems, hosts and the services that may be available. Nmap does a wonderful job of finding open ports and detecting and identifying security risks. Nmap can scale from monitoring one host to large networks that may include hundreds of thousands of devices and subnets.

Nmap has many features and capabilities but fundamentally it is a port-scan tool. Nmap sends packets to ports, monitors responses and then tags the ports as open, closed, or perhaps protected by a firewall. Port scanning is a method of ascertaining which ports on a network may be open and involved with sending or receiving data. Port scanning is also referred to as port discovery or enumeration. Port scanning is different from sniffing, which is the term to monitor traffic on a network. Port scanning is used to determine vulnerabilities on a system that is unknown.

Nmap goes back almost 24 years. Nmap was originally written in C++ and was first introduced complete with a full source listing. Nmap has been extended with C, Perl and Python and still benefits from community developers that have moved the code to Windows, macOS, a variety of Linux distributions and other operating systems.

Nmap functionality:
Nmap packets go out and then return with IP addresses and other data. This allows an astute user to map the network, ascertain network key attributes, and develop an inventory of both hardware and software. Nmap uses a variety of different protocols including TCP, UDP, SCTP, and ICMP.

Nmap is particularly noteworthy for its depth and breadth of capability and power. Nmap provides other capabilities beyond basic port mapping including:

**Service discovery:** Nmap identifies hosts and ascertains if they are acting as mail, web or name servers. Nmap can also determine the applications and versions of other software which they are using.<br>
**Network mapping:** Nmap host discovery can include servers, routers and switches, and how they’re physically connected. Host discovery is part of network reconnaissance. A threat actor or an ethical hacker would take a range of IP addresses on a target network and then use various techniques to identify the host at that IP address if one exists. This technique is also called Ping scanning.<br>
**Operating system detection:** Nmap can identify the operating system running on devices, including perhaps the vendor and software version.<br>
**Security auditing and risk assessment:** Once Nmap identifies the version and applications running on a specific host it can then further determine their open vulnerabilities. Network administrators can investigate external alerts to determine if vulnerable products and operating systems exist within their networks.<br>

**Example Nmap commands:**

Live host discovery: 🢃
```
nmap -sn -PR 192.168.1.0/24 -Pn
```

Nmap vulnerability scan: 🢃
```
sudo nmap -Pn --script vuln -sV host
```

Nmap full port scan: 🢃
```
nmap -Pn -sC -sV -T4 -A -O -p- IP
```

SSL enumeration: 🢃
```
nmap -Pn -sV --script ssl-enum-ciphers -p 443 <host>
```

## Remote Code Execution on SMB 3.1.1

Microsoft Server Message Block 3.1. 1 (SMBv3) protocol is capable of detecting interception attacks that attempt to downgrade the protocol or the capabilities that the client and server negotiate by use of pre-authentication integrity.

Remote code execution (RCE) attacks allow an attacker to remotely execute malicious code on a computer. The RCE vulnerability can range from malware execution to an attacker gaining full control over a compromised machine.

To exploit the vulnerability against a client, an unauthenticated attacker would need to configure a malicious SMBv3 server and convince a user to connect to it.
After successful exploitation could allow attackers to use shares to cause the system to crash.


## Security Response Headers Missing

Missing security response headers, such as X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, Permissions-Policy, and x-xss-protection, can have significant security impacts on the Web Server.

HTTP security headers are a set of standard HTTP response headers proposed to prevent or mitigate known XSS, clickjacking, MIME sniffing and other security vulnerabilities. These response headers define security policies to client browsers so that the browsers avoid exposure to known vulnerabilities when handling requests.


Script to check for missing security response headers:

```
var req = new XMLHttpRequest();
req.open("GET", document.location, false);
req.send(null);
var headers = req.getAllResponseHeaders().toLowerCase();
var data = [
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Permissions-Policy",
    "X-XSS-Protection"
];

console.log("\n\n");
console.log("%c---------------------Missing Headers----------------------", "color: red; font-weight: bold;");
for (var i = 0; i < data.length; i++) {
    if (headers.search(data[i].toLowerCase()) < 0) {
        console.log("%c" + data[i], "color: blue; font-weight: bold;");
    }
}
console.log("%c---------------------------------------------------------\n", "color: red; font-weight: bold;");
console.log("\n\n");
```

**Note:** Paste the above code in the website's console under the developer tab as shown in the below image

![image](https://github.com/0xKayala/A-to-Z-Vulnerabilities/assets/16838353/b32a2664-338d-492e-b1d6-00ebf3704fc2)

## SMB Work Group Enumeration with Anonymous login

SMB (Server Message Block) is a protocol used for file and printer sharing in Windows-based networks. Workgroup enumeration is a process where an attacker tries to gather information about the systems present in the same workgroup or network by exploiting anonymous login vulnerabilities. In a workgroup, systems can be configured to allow anonymous access, which means users can connect to network shares without providing any credentials.

Description of SMB Workgroup Enumeration with Anonymous Login:

1. Discovery Phase: The attacker scans the network for available systems by sending SMB requests to the IP addresses within the network range. During this process, they identify systems that respond to anonymous SMB requests.<br>

2. Enumeration Phase: Once the attacker identifies systems with anonymous access enabled, they can query for information such as the list of shares (shared folders) available on those systems, as well as user accounts and other system information. This gives the attacker valuable insights into potential targets and vulnerable points.

Command to test for SMB Workgroup Enumeration with Anonymous Login:
1. `enum4linux -a IP`

## SQL Injection

SQL injection is a type of attack where an attacker can execute malicious SQL code by inserting them into an entry field on a website or application that interacts with a database. The attacker can exploit vulnerabilities in the code of the website or application to bypass security measures and gain unauthorized access to the database. Once the attacker has gained access to the database, they can extract sensitive information such as usernames, passwords, and credit card details, or modify or delete data stored in the database.

Mitigation:
1) Use parameterized queries: This involves using prepared statements or parameterized queries, which separate the SQL code from the user input. This prevents the attacker from injecting SQL code directly into the query.
2) Validate user input: Ensure that user input is validated before it is used in a SQL query. This includes validating the data type, length, and format of the input.
3) Limit user privileges: Use the principle of least privilege to restrict the privileges of users who have access to the database. This reduces the potential damage that can be caused by a successful SQL injection attack.
4) Implement firewalls and access controls: Use firewalls and access controls to restrict the access to the database to only authorized users. This reduces the likelihood of an attacker gaining access to the database and being able to carry out a successful SQL injection attack.


Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196904420-c6da73f9-d2f4-4b55-abac-bfbaa683878e.png)

### In-band SQLi

The attacker uses the same channel of communication to launch their attacks and to gather their results. In-band SQLi’s simplicity and efficiency make it one of the most common types of SQLi attack. There are two sub-variations of this method:

#### Error-based SQLi

Attacker tries to insert malicious query in input fields and get some error which is regarding SQL syntax or database. The error message gives information about the database used, where the syntax error occurred in the query. Error based technique is the easiest way to find SQL Injection

#### Union-based SQLi

Union based SQL injection allows an attacker to extract information from the database by extending the results returned by the original query. The Union operator can only be used if the original/new queries have the same structure (number and data type of columns)

### Blind SQLi

The attacker sends data payloads to the server and observes the response and behavior of the server to learn more about its structure. This method is called blind SQLi because the data is not transferred from the website database to the attacker, thus the attacker cannot see information about the attack in-band. Blind SQL injections rely on the response and behavioral patterns of the server so they are typically slower to execute but may be just as harmful.
Blind SQL injections can be classified as follows:

#### Boolean

Attacker sends a SQL query to the database prompting the application to return a result. The result will vary depending on whether the query is true or false. Based on the result, the information within the HTTP response will modify or stay unchanged. The attacker can then work out if the message generated a true or false result.

#### Time-based

Attacker sends a SQL query to the database, which makes the database wait (for a period in seconds) before it can react. The attacker can see from the time the database takes to respond, whether a query is true or false. Based on the result, an HTTP response will be generated instantly or after a waiting period. The attacker can thus work out if the message they used returned true or false, without relying on data from the database.

### Out-of-band SQLi

Out-of-band SQL injection is a specific type of SQL injection where the attacker does not receive a response from the attacked application on the same communication channel but instead is able to cause the application to send data to a remote endpoint that they control. Out-of-band SQL injection is only possible if the server that you are using has commands that trigger DNS or HTTP requests.

## Security Misconfiguration

Security misconfigurations are security controls that are inaccurately configured or left insecure, putting your systems and data at risk. Basically, any poorly documented configuration changes, default settings, or a technical issue across any component in your endpoints could lead to a misconfiguration.
Misconfigurations are often seen as an easy target, as it can be easy to detect on misconfigured web servers, cloud and applications and then becomes exploitable, causing significant harm and leading to catastrophic data leakage issues for enterprises like the 2019 Teletext exposure of 530,000 data files which was caused by an insecurely configured Amazon Web Service (AWS) web server. Unfortunately, once a system falls prey to a vulnerability or lack of security safeguarding, your sensitive data is at risk of getting stolen or altered.

## Software and Data Integrity Failures

Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This can occur when you use software from untrusted sources and repositories or even software that has been tampered with at the source, in transit, or even the endpoint cache.
Attackers can exploit this to potentially introduce unauthorized access, malicious code, or system compromise as part of the following attacks:
1) Cache Poisoning
2) Code injection
3) Command execution
4) Denial of Service

The SolarWinds Orion attack in which highly targeted malicious updates were distributed to more than 18,000 organizations is one of the most significant breaches of this nature.

## Security Logging and Monitoring Failures

Security logging and monitoring failures are frequently a factor in major security incidents. The BIG-IP system includes advanced logging and monitoring functionality and provides security features to protect against attacks that can result from insufficient system and application logging and monitoring. Failure to sufficiently log, monitor, or report security events, such as login attempts, makes suspicious behavior difficult to detect and significantly raises the likelihood that an attacker can successfully exploit your application. For example, an attacker may probe your application or software components for known vulnerabilities over a period. Allowing such probes to continue undetected increases the likelihood that the attacker ultimately finds a vulnerability and successfully exploits the flaw. Insufficient logging, monitoring, or reporting makes your application susceptible to attacks that target any part of the application stack.

For example, the following attack types may result from a failure to log, monitor, or report security events:
1) Code injection
2) Buffer overflow
3) Command injection
4) Cross-site scripting (XSS)
5) Forceful browsing

## Server-side Request Forgery

Server-side request forgery (SSRF) flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.
The vulnerable web application will often have privileges to read, write, or import data using a URL. To execute an SSRF attack, the attacker abuses the functionality on the server to read or update internal resources.
The attacker can then force the application to send requests to access unintended resources, often bypassing security controls.

Successful SSRF attacks can result in the following:
1) Exposure and theft of data that may include sensitive personal or corporate information
2) Unauthorized manipulation of sensitive data
3) Hijack of a vulnerable system to use its trust relationship with other systems to launch further attacks

## Server Side Template Injection

Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.
Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. This allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server. As the name suggests, server-side template injection payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196879302-8b4ab854-9240-442f-99d9-46535ac44d1a.png)

## Vulnerable and Outdated components

A software component is part of a system or application that extends the functionality of the application, such as a module, software package, or API. Component-based vulnerabilities occur when a software component is unsupported, out of date, or vulnerable to a known exploit. You may inadvertently use vulnerable software components in production environments, posing a threat to the web application. For example, an organization may download and use a software component, such as OpenSSL, and fail to regularly update or patch the component as flaws are discovered. Since many software components run with the same privileges as the application itself, any vulnerabilities or flaws in the component can result in a threat to the web application.

## XML External Entity

XXE (XML External Entity Injection) is a common web-based security vulnerability that enables an attacker to interfere with the processing of XML data within a web application.  
While XML is an extremely popular format used by developers to transfer data between the web browser and the server, this results in XXE being a common security flaw.
XML requires a parser, which is typically where vulnerabilities occur. XXE enables an entity to be defined based on the content of a file path or URL. When the XML attack payload is read by the server, the external entity is parsed, merged into the final document, and returns it to the user with the sensitive data inside. 
XXE attacks can result in port scanning within the internal network, server-side request forgery (SSRF), data exfiltration, use of an organization’s servers to perform denial of service (DoS), and more.

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![image](https://user-images.githubusercontent.com/16838353/196876341-7f06aaaf-4ff5-4bc5-922b-ead822d6ccbf.png)

## Contributing 
- To Contribute in this Repo Send me direct message to My Twitter: [0xKayala](https://twitter.com/0xKayala)

## Maintainers 

`This Repo is maintained by: `

- [Satya Prakash](https://github.com/0xKayala)
