# Vulnerable Driver Queries

Microsoft itself has a list of known-malicious Drivers (**Microsoft 'Vulnerable Driver Blocklist'**) which are automatically remediated on any load action when the security setting is enabled.

That said, the queries in this repo aim to fill in potential gaps by sourcing drivers from other sources (more sources to come soon!) in order to catch upcoming drivers that might not yet be in Microsoft's official list. 

Currently, this alert sources entries from the LOLDrivers website hash repository: https://www.loldrivers.io/ 

&nbsp;

### > BYOVD-DriverLoad.kusto
This query will alert when a known driver in the LOLDrivers list loads in your environment. This should only be successful loads, so this is a good query to alert on.

---

### > BYOVD-KnownDriverScan.kusto
This query is more noisy because it will scan your environment for existing hashes which match known drivers in the LOLDrivers list. 

This differs from the DriverLoad query because the Load Events alerts on successful driver loads, whereas this scans your environment across the designated time range searching for the existence of these hashes. 
