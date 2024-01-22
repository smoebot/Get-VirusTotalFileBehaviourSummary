# Get-VirusTotalFileBehaviourSummary

Powershell. Search the VirusTotal API for a known file and return the file behaviour

Returns detail about files written, files dropped, dns lookups, signatures, processes, etc

---

**Parameters**

_Hash_

The hash of the file that that you wish to look up on VirusTotal. This can be a MD5, SHA, or SHA256 hash

---

**Examples**

Get-VirusTotalFileTtps -Hash 4AFB41FB9E64023B6EC5BA5107E52B689A66490C971F5B54B2BB20691D610D2C
