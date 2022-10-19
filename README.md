# A-to-Z-Vulnerabilities [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> This is a Kind of Dictionary which contains about all kinds of Web Application Vulnerabilities in Alphabetical Order

## Contents

- [Broken Access Control](#Broken-Access-Control)
- [Insecure Direct Object Reference](#Insecure-Direct-Object-Reference (IDOR))
- [Cross-site Request Forgery (CSRF)](#Cross-site-Request-Forgery (CSRF))
- [Cross-Origin Resource Sharing (CORS)](#Cross-Origin-Resource-Sharing (CORS))
- [Directory traversal or Path Traversal](#Directory-traversal-or-Path-Traversal)
- [Forced browsing](#Forced-browsing)


---

## Broken Access Control

Broken access control means that an attackers can gain access to user accounts and act as users or administrators by which he can gain unintended privileged functions. In Simple terms, broken access control happens when the application allows a user to perform unauthorized actions. There are many vulnerabilities which contribute to this risk, For instance, if the developer forgets to validate permissions when dealing with identifiers, the application becomes vulnerable to Insecure Direct Object Reference (IDOR). Other vulnerabilities include Cross-site Request Forgery (CSRF), Cross-Origin Resource Sharing (CORS) misconfigurations, directory traversal and forced browsing

## Insecure Direct Object Reference (IDOR)

Insecure Direct Object Reference (IDOR) - This vulnerability happens when the application doesn’t properly validate access to resources through IDs. For example, an application shows a purchase order to the customer using the /orders/1234 endpoint. However, the user whose order id is 1234 can also access other orders by simply changing the order id. This is the simplest scenario, but there are many other techniques to exploit an IDOR vulnerability

## Cross-site Request Forgery (CSRF)

Cross-site Request Forgery (CSRF) - Cross-Site Request Forgery is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. Using CSRF, a hacker can forge a request from a legitimate website to the unsuspecting logged in user. By sending this forged link via email or chat, an attacker can trick the users of a web application into executing actions of the attacker’s choosing

## Cross-Origin Resource Sharing (CORS)

Cross-Origin Resource Sharing (CORS) - Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP). However, it also provides potential for cross-domain attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as cross-site request forgery (CSRF)

## Directory traversal or Path Traversal

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

## Forced browsing

A Forced browsing attack is a vulnerability in which an unauthorized user has access to the contents of an authorized user. Forced browsing is an attack when a Web application has more than one user privilege level for the same user. Thus, an attacker gets sensitive information which should otherwise not be accessible to him/her.The attacker can use a brute force approach to get common directories, files, or information of user accounts present on the website.
