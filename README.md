# A-to-Z-Vulnerabilities [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> This is a Kind of Dictionary which contains about all kinds of Web Application Vulnerabilities in Alphabetical Order

## Contents

- [Authentication Bypass](#Authentication-Bypass)
- [Broken Access Control](#Broken-Access-Control)
- [Cross-site Request Forgery](#Cross-site-Request-Forgery)
- [Cross-Origin Resource Sharing](#Cross-Origin-Resource-Sharing)
- [Cryptographic Failures](#Cryptographic-Failures)
- [Code Injection](#Code-Injection)
- [Command injection](#Command-injection)
- [Directory traversal or Path Traversal](#Directory-traversal-or-Path-Traversal)
- [Forced browsing](#Forced-browsing)
- [Injection](#Injection)
- [Insecure Direct Object Reference](#Insecure-Direct-Object-Reference)
- [SQL Injection](#SQL-Injection)
    - [In-band SQLi](#In-band-SQLi)
        - [Error-based SQLi](#Error-based-SQLi)
        - [Union-based SQLi](#Union-based-SQLi)
    - [Blind SQLi](#Blind-SQLi)
        - [Boolean](#Boolean)
        - [Time-based](#Time-based)
    - [Out-of-band SQLi](#Out-of-band-SQLi)


---

## Authentication Bypass

An attacker gains access to application, service, or device with the privileges of an authorized or privileged user by evading or circumventing an authentication mechanism. The attacker is therefore able to access protected data without authentication ever having taken place. This refers to an attacker gaining access equivalent to an authenticated user without ever going through an authentication procedure. This is usually the result of the attacker using an unexpected access procedure that does not go through the proper checkpoints where authentication should occur. For example, a web site might assume that all users will click through a given link in order to get to secure material and simply authenticate everyone that clicks the link. However, an attacker might be able to reach secured web content by explicitly entering the path to the content rather than clicking through the authentication link, thereby avoiding the check entirely. This attack pattern differs from other authentication attacks in that attacks of this pattern avoid authentication entirely, rather than faking authentication by exploiting flaws or by stealing credentials from legitimate users.

## Broken Access Control

Broken access control means that an attackers can gain access to user accounts and act as users or administrators by which he can gain unintended privileged functions. In Simple terms, broken access control happens when the application allows a user to perform unauthorized actions. There are many vulnerabilities which contribute to this risk, For instance, if the developer forgets to validate permissions when dealing with identifiers, the application becomes vulnerable to Insecure Direct Object Reference (IDOR). Other vulnerabilities include Cross-site Request Forgery (CSRF), Cross-Origin Resource Sharing (CORS) misconfigurations, directory traversal and forced browsing

Image Credits: https://www.geeksforgeeks.org/

![BAC](https://user-images.githubusercontent.com/16838353/196788103-8f86536d-cd1b-41b2-9777-2e0d88e3e4d3.png)

## Cross-site Request Forgery

Cross-site Request Forgery (CSRF) - is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. Using CSRF, a hacker can forge a request from a legitimate website to the unsuspecting logged in user. By sending this forged link via email or chat, an attacker can trick the users of a web application into executing actions of the attacker’s choosing

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![CSRF](https://user-images.githubusercontent.com/16838353/196786974-d30c9660-7453-4b0f-bca0-897c21a1ebe6.jpg)

## Cross-Origin Resource Sharing

Cross-Origin Resource Sharing (CORS) - is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP). However, it also provides potential for cross-domain attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as cross-site request forgery (CSRF)

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![cors](https://user-images.githubusercontent.com/16838353/196784777-b5ab1c7a-46e9-465f-82c9-4749617dfdd6.png)

## Cryptographic Failures

A cryptographic failure is a critical web application security vulnerability that exposes sensitive application data on a weak or non-existent cryptographic algorithm. These can be passwords, patient health records, business secrets, credit card information, email addresses, or other personal user information. Apart from exposing sensitive information, as cryptographic failures can also compromise systems, the implications of this vulnerability are considered one of the most critical security risks for both organizations and business users

## Code Injection

Code injection is one of the most common types of injection attacks. If attackers know the programming language, the framework, the database or the operating system used by a web application, they can inject code via text input fields to force the webserver to do what they want. These types of injection attacks are possible on applications that lack input data validation. If a text input field lets users enter whatever they want, then the application is potentially exploitable. To prevent these attacks, the application needs to restrict as much as it can the input users are allowed to enter. For example, it needs to limit the amount of expected data, to check the data format before accepting it, and to restrict the set of allowed characters.

## Command injection

Sometimes web applications need to call a system command on the webserver that is running them. In such instances, if user input is not validated and restricted, a command injection can occur. Unlike code injections, command injections only require the attacker to know the operating system used. Then, the attacker inserts a command into the system, using the user privileges. The inserted command then executes in the host system. A command injection can compromise that application, its data, the entire system, connected servers, systems, and other infrastructure.

## Directory traversal or Path Traversal

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

## Forced browsing

A Forced browsing attack is a vulnerability in which an unauthorized user has access to the contents of an authorized user. Forced browsing is an attack when a Web application has more than one user privilege level for the same user. Thus, an attacker gets sensitive information which should otherwise not be accessible to him/her.The attacker can use a brute force approach to get common directories, files, or information of user accounts present on the website.

## Injection

During an injection attack, an attacker can provide malicious input to a web application (inject it) and change the operation of the application by forcing it to execute certain commands. An injection attack can expose or damage data and lead to a denial of service or a full web server compromise. Such attacks are possible due to vulnerabilities in the code of an application that allows for unvalidated user input. Injection attacks are one of the most common and dangerous web attacks. Injection vulnerability is ranked #1 in the OWASP Top Ten Web Application Security Risks. Several injection attacks are also featured in the Common Weakness Enumeration (CWE)

## Insecure Direct Object Reference

Insecure Direct Object Reference (IDOR) - This vulnerability happens when the application doesn’t properly validate access to resources through IDs. For example, an application shows a purchase order to the customer using the /orders/1234 endpoint. However, the user whose order id is 1234 can also access other orders by simply changing the order id. This is the simplest scenario, but there are many other techniques to exploit an IDOR vulnerability

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![idor](https://user-images.githubusercontent.com/16838353/196786238-4f9b3874-c0bf-413f-972d-eb8c688fb013.jpg)

## SQL Injection

In a similar way to code injection, this attack inserts an SQL script –the language used by most databases to perform query operations– in a text input field.
The script is sent to the application, which executes it directly on its database. As a result, the attacker could pass through a login screen or do more dangerous things, like read sensitive data directly from the database, modify or destroy database data, or execute admin operations on the database. PHP and ASP applications are prone to SQL injection attacks due to its older functional interfaces. J2EE and ASP.Net apps are usually more protected against these attacks. When an SQL injection vulnerability is found –and they could be easily found–the magnitude of the potential attacks will only be limited by the attacker’s skill and imagination. Thus, the impact of an SQL injection attack is undoubtedly high.

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
