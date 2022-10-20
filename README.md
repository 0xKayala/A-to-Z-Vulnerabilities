# A-to-Z-Vulnerabilities [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> This is a Kind of Dictionary which contains about all kinds of Web Application Vulnerabilities in Alphabetical Order

## Contents

- [Authentication Bypass](#Authentication-Bypass)
- [Broken Access Control](#Broken-Access-Control)
- [Cross-site Request Forgery](#Cross-site-Request-Forgery)
- [Cross-Origin Resource Sharing](#Cross-Origin-Resource-Sharing)
- [Directory traversal or Path Traversal](#Directory-traversal-or-Path-Traversal)
- [Forced browsing](#Forced-browsing)
- [Insecure Direct Object Reference](#Insecure-Direct-Object-Reference)


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

## Directory traversal or Path Traversal

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

## Forced browsing

A Forced browsing attack is a vulnerability in which an unauthorized user has access to the contents of an authorized user. Forced browsing is an attack when a Web application has more than one user privilege level for the same user. Thus, an attacker gets sensitive information which should otherwise not be accessible to him/her.The attacker can use a brute force approach to get common directories, files, or information of user accounts present on the website.

## Insecure Direct Object Reference

Insecure Direct Object Reference (IDOR) - This vulnerability happens when the application doesn’t properly validate access to resources through IDs. For example, an application shows a purchase order to the customer using the /orders/1234 endpoint. However, the user whose order id is 1234 can also access other orders by simply changing the order id. This is the simplest scenario, but there are many other techniques to exploit an IDOR vulnerability

Source: https://securityzines.com/ |
Image Credits: https://twitter.com/sec_r0

![idor](https://user-images.githubusercontent.com/16838353/196786238-4f9b3874-c0bf-413f-972d-eb8c688fb013.jpg)
