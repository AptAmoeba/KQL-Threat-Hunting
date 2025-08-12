# Phishing Queries
These queries are designed for hunting individual email vectors. Each query should serve its own purpose, and each should generally be designated as a Hunting or Alerting query. Hunting queries will return more noise, but help investigations. Alerting queries are tuned to alert on meaningful, more urgent events.

&nbsp;

## Query Usage:

### > Mirror Masquerade Spoofing (Alert)

This query alerts on spoofing where both the header & server FROM addresses equal the recipient address 

(e.g.: sender: jsmith@contoso.com --> recipient: jsmith@contoso.com)

&nbsp;

**Output Comprehension & Incident Response:**

- **Find Payload Downloads**: Simply click the Hash in the output of the query to scan your environment for matches.
- **Find Non-Download Executions**: use the following below:

```kql
DeviceEvents
| where ActionType == 'NamedPipeEvent'
| where parse_json(AdditionalFields)["FileOperation"] =~ "File opened"
| where FileName == "<FileName from phish>"
```

&nbsp;

**Planned Updates:**
- Automatically check whether a user interacted with the payload via either method (Download or direct-execution)!
- Separate this query into two, where:
  - **Query 1 (Hunt)**: The current query, which searches emails for any instance of a this spoof vector, regardless of whether it has an attachment, and regardless of whether a user clicked it.
  - **Query 2 (Alert)**: A query tuned for alerting, triggering when a user has executed/downloaded the payload; this will be a better alert, because it won't be unnecessarily noisy.

---

