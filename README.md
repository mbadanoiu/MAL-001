# MAL-001: FreeMarker Server-Side Template Injection in Liferay Portal

An issue was discovered in Liferay - Portal <=7.4.3.12-ga12. By inserting malicious content in the FTL Templates, an attacker may perform SSTI (Server-Side Template Injection) attacks, which can leverage FreeMarker exposed objects to bypass restrictions and perform SSRF (Server-Side Request Forgery), read arbitrary files and/or obtain RCE (Remote Code Execution).

<strong>Note:</strong> This issue exists because of an incomplete fix for CVE-2020-13445.

### Why no CVE?

[Liferay](https://www.cve.org/PartnerInformation/ListofPartners/partner/Liferay) is part of the [MITRE CNAs](https://www.cve.org/ProgramOrganization/CNAs) program and have decided that, because of the user privileges required to exploit the SSTI, the vulnerability does not represent a high enough risk to warant a CVE or a security advisory.

### Requirements:

This vulnerability requires:
<br/>
- Valid user credentials with the role "Power User", "Site Administrator" or "Site Owner"

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/MAL-001/blob/main/Liferay%20-%20MAL-001.pdf).

### Additional Resources:

Initial [vulnerability (CVE-2020-13445)](https://nvd.nist.gov/vuln/detail/CVE-2020-13445) and [blogpost](https://securitylab.github.com/advisories/GHSL-2020-043-liferay_ce/) by [Alvaro "pwntester" Munoz](https://github.com/pwntester) that inspired the SSTI research and finding of this vulnerability.

HSQL RCE vector was inspired by the blogpost ["Remote Code Execution in F5 Big‑IP" by Mikhail Klyuchnikov](https://swarm.ptsecurity.com/rce-in-f5-big-ip/).

### Timeline:

- This vulnerability was initially reported to security@liferay.com on 26-Feb-2022
- Vulnerability was considered a non-issue as "permission to edit templates should only be granted to trusted users"
- Retested the vulnerability on 18-Jan-2023 and noticed that:
  - The Arbitrary File Read and SSRF vectors have been patched
  - The RCE had been remediated by the HSQL patch for CVE-2022-41853
- Publically disclosed the vulnerability on 03-Jan-2024
