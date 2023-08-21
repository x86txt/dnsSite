<p align="center">
<h2 align="center">a simple dns api built with python and the flask framework</h2>
</p>
<br />
<p align="center">
<a href="https://www.gnu.org/licenses/gpl-3.0.html"><img src="https://img.shields.io/badge/license-GPLv3-red?style=flat-square" alt="GPLv3"></a>
<img src="https://img.shields.io/badge/python-3.10-darkgreen?style=flat-square&logo=flask"></i>
<img src="https://img.shields.io/github/actions/workflow/status/x86txt/dnssite/zappa.yml?style=flat-square&logo=githubactions"></i>
<a href="https://github.com/x86txt/dnsSite/security/code-scanning"><img src="https://github.com/x86txt/dnsSite/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main"></i></a>
<a href="https://dns.secunit.io/"><img src="https://betteruptime.com/status-badges/v1/monitor/pyr7.svg"></a><br />
Want to try a Live Version? Click the Uptime button above.
</p>
&nbsp;
&nbsp;
> [!IMPORTANT]  
> 08/21/2023: a recent security package update has broken several api routes, including ptr and dkim lookups. these will be fixed soon. 
&nbsp;
&nbsp;
## `curl example:`
```
$ curl https://dns.secunit.io/api/a/secunit.io
{"addr":"104.21.4.4","hostname":"secunit.io"}

$ curl https://dns.secunit.io/api/spf/secunit.io
{"result":"v=spf1 include:sendgrid.net mx include:spf.protection.outlook.com -all","spf":"secunit.io"}

$ curl 
```
