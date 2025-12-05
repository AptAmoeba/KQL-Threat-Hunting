```kql
// Created by AptAmoeba/BunchOfWetFrogs
// B2B Teams Invite to User from External Tenant (Potential Phishing/Disallowed Tenant Collaboration Hunting) 
// This will catch all External Teams Invites, which will include phishing messages. Check the "Supposed 'Teams Group Name'" section to evaluate. 
//
let ConnectionChecker = EntraIdSignInEvents //Checking if Recipients have connected to the External Tenant Before
| where Application contains "Teams"
| where IsGuestUser == 1
| extend User = tolower(extract(@"^([^@]+)@", 1, tostring(AccountUpn)))
| extend ResourceTenantId = tostring(ResourceTenantId)
| summarize ConnectedToTenant = any(true), SignInCount = count(), FirstSignInTime = min(Timestamp) by ResourceTenantId, User;
//
let B2BInvRecipients = EmailEvents //Identifying Recipients of Teams B2B Invitations
| where SenderMailFromAddress contains "teams.mail.microsoft"
| where Subject contains "You have been added"
| where InternetMessageId startswith "<InviteGuestMember"
| extend User = tolower(extract(@"^([^@]+)@", 1, tostring(RecipientEmailAddress)))
| extend TenantId = tostring(extract(@"(?i)tid_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", 1, InternetMessageId))
// ^ You can technically also extract the TID from the URL, but Email Security Providers often rewrite URLs prior to delivery so this is more consistent.
| extend PhishMessage = tostring(extract(@"(?is)guest to\s*(.*)\s*in Microsoft Teams", 1, Subject))
// Example phish message: "You have been added as a guest to MX805242 Amount 589. 98 USD). If this payment was not made by you or you suspect any issue, please reach our support immediately at +1 nnn 220 2947 for urgent assistance. in Microsoft Teams"
| extend PhishMessage = iff(isempty(PhishMessage), "", trim(' ', replace_regex(PhishMessage, @"\s+", " ")))
| extend TenantResolution = iff(isempty(TenantId), "", strcat("https://tenantidlookup.com/", tostring(TenantId)))
// ^ You can copy/paste the resulting URL to grab more information on the Tenant, like: Name, Approx. Location, Mail Records, etc.
| project Timestamp, RecipientEmailAddress, ["Supposed 'Teams Group Name'"] = PhishMessage, ["(Sender) Tenant ID"]=TenantId, ["Tenant Information"]=TenantResolution, ["Full Subject"]=Subject, InternetMessageId, NetworkMessageId, User, ReportId;
//
B2BInvRecipients
| join kind=leftouter (ConnectionChecker) on $left.["(Sender) Tenant ID"] == $right.ResourceTenantId and $left.User == $right.User
| extend UserConnectedStatus = coalesce(ConnectedToTenant, false)
| project Timestamp, RecipientEmailAddress, ["Supposed 'Teams Group Name'"], ["(Sender) Tenant ID"], ["Tenant Information"], ["Full Subject"], InternetMessageId, NetworkMessageId, ["User Connected to Tenant?"]=UserConnectedStatus, FirstSignInTime, ReportId
```

## Visual Campaign
<img width="1395" height="656" alt="TeamsPhish" src="https://github.com/user-attachments/assets/bdab55d6-517d-415f-906a-b38d27737805" />

&nbsp;

Query Output:
<img width="1266" height="429" alt="B2BPhishOutput" src="https://github.com/user-attachments/assets/d2eb9643-f944-4558-be40-e557b31251df" />

- "Tenant Information" provides a URL that will resolve more information about that tenant (Name, Approx. location, Connection status, etc.)
- "User Connected to Tenant?" is a Boolean that will parse your EntraIdSignInEvents to identify whether the user has clicked the link or previously joined the remote (attacker-controlled) Tenant as a Guest.
- "Supposed 'Teams Group Name'" is technically the name of the Teams Group, but phishing often adds the phish message to this section. Manually evaluate whether this looks like phishing.

## Checking Historic Connections to a Tenant Once a Remote TenantID + User is Known

```kql
EntraIdSignInEvents
| where ResourceTenantId == "<TenantID>"// <-- ID from prev. query
| where Application contains "Teams"// Remove this to see all Tenant Application connections
| extend User = tolower(extract(@"^([^@]+)@", 1, tostring(AccountUpn)))
| where IsGuestUser == 1 // This catches when our users are guests in external tenants
| where User == "<user>"// <-- User from prev. query
| order by Timestamp desc
//| summarize SignInCount = count() by ResourceTenantId, User; //Uncomment to get a count of Signins from the User to the Tenant 
```
