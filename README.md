# A-to-Z-Vulnerabilities [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> This is a Kind of Dictionary which contains about all kinds of Web Application Vulnerabilities in Alphabetical Order

## Contents

- [Broken Access Control](#Broken-Access-Control)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
    - [Port Scanning](#Port-Scanning)
    - [Screenshots](#Screenshots)
    - [Technologies](#Technologies)
    - [Content Discovery](#Content-Discovery)
    - [Links](#Links)
    - [Parameters](#Parameters)
    - [Fuzzing](#Fuzzing)

---

## Broken Access Control

Broken access control means that an attackers can gain access to user accounts and act as users or administrators by which he can gain unintended privileged functions. In Simple terms, broken access control happens when the application allows a user to perform unauthorized actions. There are many vulnerabilities which contribute to this risk, For instance, if the developer forgets to validate permissions when dealing with identifiers, the application becomes vulnerable to Insecure Direct Object Reference (IDOR). Other vulnerabilities include Cross-site Request Forgery (CSRF), Cross-Origin Resource Sharing (CORS) misconfigurations, directory traversal and forced browsing

### Subdomain Enumeration

- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Fast subdomains enumeration tool for penetration testers
- [Amass](https://github.com/OWASP/Amass) - In-depth Attack Surface Mapping and Asset Discovery
- [massdns](https://github.com/blechschmidt/massdns) - A high-performance DNS stub resolver for bulk lookups and reconnaissance (subdomain enumeration)
