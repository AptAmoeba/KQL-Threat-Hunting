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
//Historic Successful Tenant Connection Lookup
EntraIdSignInEvents
| where ResourceTenantId == "<TenantID>"// <-- ID from prev. query
| where Application contains "Teams"// Remove this to see all Tenant Application connections
| extend User = tolower(extract(@"^([^@]+)@", 1, tostring(AccountUpn)))
| where IsGuestUser == 1 // This catches when our users are guests in external tenants
| where User == "<user>"// <-- User from prev. query
| order by Timestamp desc
//| summarize SignInCount = count() by ResourceTenantId, User; //Uncomment to get a count of Signins from the User to the Tenant 
```

&nbsp;

## >WARNING

[!] Remote Tenants can still add your users as Guests without sending Teams invites. If your user does not connect to them, there will not be record of their connection in the Historic Connections section either, nor will there be an alert for the Teams phishing vector.

However, from your User's perspective, they will get a banner within Teams telling them that a new Tenant has added them. They will have to manually Leave the Tenant ("Go To Settings" > Leave):

<img width="1903" height="86" alt="Example-B2B-User-Added-as-Guest-Banner" src="https://github.com/user-attachments/assets/c106424e-4bb7-4833-b5cf-74ec20fc3078" />


To tighten restrictions on these, I suggest completely blocking B2B invites. You can manually whitelist them afterwards, as the whitelist takes precedence above the baseline block ([External Tenant Access Auditing - MS](https://techcommunity.microsoft.com/discussions/microsoft-entra/audit-users-to-view-who-are-guests-in-other-tenants/4390435))

&nbsp;

To get a preliminary whitelist for the most common legitimate B2B connections, you may use this query that I wrote:

```kql
// Pull all active Tenant connections and sort by prevalence, with the ability to add Application context.
// Additionally added a custom URL to resolve Remote Tenant's Name.
EntraIdSignInEvents 
| where Timestamp >ago(90d)
| where ResourceTenantId != "<Your Tenant ID>"
//| where AccountUpn contains "<user>"
| where IsGuestUser == 1
| distinct ResourceTenantId, AccountUpn//, Application
//Generate a URL to resolve the Remote Tenant's Name:
| extend TenantResolution = iff(isempty(ResourceTenantId), "", strcat("https://tenantidlookup.com/", tostring(ResourceTenantId)))
| summarize SignInCount = count() by ResourceTenantId, TenantResolution//, Application
//| where SignInCount > 1 //Uncomment to ignore all single-connection events.
| sort by SignInCount desc
```

I suggest adding the most common ones to the whitelist, and then enforcing the Block List. Anyone who then needs to regain access to legitimate Tenants can submit a ticket for review.
