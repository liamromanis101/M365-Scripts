# M365-Scripts
Collection of scripts for testing M365 subscriptions (& Azure). Most of these scripts assume that access has been gained with a low privilege user account or that you are performing testing as a typical user where you do not have access to powershell. These scripts are intended for educational purposes or for authorized security assessments. 



## Legacy Services:
(legacyservices.py) - removed because of reasons.. will be back soon
Requires requests and msal
[pip install msal requests]

This script attempts to identify legacy services which have not been disabled by attempting to login to them with a M365 user account. The script also tries to 'guess' domains for SharePoint, SharePoint SOAP Service and ADFS from the email address used to login. 

Legacy Services do not support MFA and therefore APTs will attempt to brute force accounts using these services or access M365 using these services with previously discovered accounts. 

## Current User's Privileges
(get-my-privs.py)
Requires subprocess, requests and json
[pip install subprocess requests json]

This script attempts to enumerate the roles and groups that the current account has using graph requests. 

(get-my-graph-priv.py)
Requires subprocess, requests and json
[pip install subprocess requests json]

This script enumerates granted graph permissions by making requests to key graph endpoints. 

## Enumerate User accounts
(getusers.py)
Requires subprocess, requests and json
[pip install subprocess requests json]

This script enumerates all user accounts using the graph /users endpoint. It avoids Graph pagination issues and prints out all user accounts. 

(get-users-privs.py)
Requires subprocess, requests and json
[pip install subprocess requests json]

This script enumerates all users and then requests all role and group membership information for each user. 

## OAuth2 Token Theft
(oauth2-token-risky-scopes.py)
Requires os, subprocess, json, requests
[pip install os subprocess json requests]

This script analyzes OAuth2 permissions granted to applications within the tenant. The script helps identify potential risks associated with OAuth token theft by examining the permissions granted to applications, particularly those with overly permissive scopes.

The following scopes are considered risky, especially if granted to applications not fully trusted by your organization:

1. full_access_as_user

	•	Description: Allows the app to have full access to the user’s data. This is typically used by apps that require the same level of access as the signed-in user.
	•	Risk: The app can access all data the user has access to, which can include emails, files, and other sensitive information.

2. User.ReadWrite.All

	•	Description: Allows the app to read and write all users’ full profiles, including their directory data.
	•	Risk: The app can modify user profiles across the entire tenant, potentially altering key information or injecting malicious data.

3. Mail.ReadWrite

	•	Description: Allows the app to read and write the signed-in user’s mail.
	•	Risk: The app can access, modify, or delete the user’s emails, potentially leading to data exfiltration or impersonation.

4. Mail.Send

	•	Description: Allows the app to send mail as the signed-in user.
	•	Risk: The app can send emails on behalf of the user, which could be used to spread phishing attacks or malware.

5. Files.ReadWrite.All

	•	Description: Allows the app to read and write all files the user can access.
	•	Risk: The app can access, modify, or delete files across SharePoint, OneDrive, and other locations, potentially leading to data loss or leaks.

6. Group.ReadWrite.All

	•	Description: Allows the app to create, read, update, and delete Microsoft 365 groups and manage group memberships.
	•	Risk: The app can modify group memberships and group data, potentially escalating privileges by adding users to groups with elevated access.

7. Directory.ReadWrite.All

	•	Description: Allows the app to read and write directory data.
	•	Risk: The app can modify directory settings and objects, potentially altering critical configuration or user data across the tenant.

8. Calendars.ReadWrite

	•	Description: Allows the app to read and write the signed-in user’s calendar events.
	•	Risk: The app can access and modify calendar events, which could lead to privacy issues or social engineering opportunities.

9. Contacts.ReadWrite

	•	Description: Allows the app to read and write the signed-in user’s contacts.
	•	Risk: The app can access and modify contacts, which could be used for targeted phishing attacks.

10. Notes.ReadWrite.All

	•	Description: Allows the app to read and write the user’s OneNote notebooks.
	•	Risk: The app can access and modify OneNote notebooks, which may contain sensitive information.

11. Tasks.ReadWrite

	•	Description: Allows the app to read and write tasks in the signed-in user’s mailbox.
	•	Risk: The app can modify task lists, potentially interfering with the user’s productivity or leaking sensitive information.

12. People.ReadWrite

	•	Description: Allows the app to read and write the signed-in user’s people data.
	•	Risk: The app can modify the user’s people-related data, which could be used for social engineering or targeted attacks.

13. DeviceManagementApps.ReadWrite.All

	•	Description: Allows the app to read and write properties of mobile apps in the organization’s directory.
	•	Risk: The app can modify or deploy mobile apps within the organization, potentially leading to the installation of malicious software.

14. Sites.FullControl.All

	•	Description: Allows the app to have full control of all site collections without a signed-in user.
	•	Risk: The app can access and manage all SharePoint sites, potentially leading to data breaches or unauthorized changes.

15. TeamSettings.ReadWrite.All

	•	Description: Allows the app to read and write settings for all teams.
	•	Risk: The app can modify team settings, which might be used to alter communication channels or add unauthorized members.

16. AuditLog.Read.All

	•	Description: Allows the app to read all audit log data in the tenant.
	•	Risk: The app can access audit logs, potentially allowing an attacker to cover their tracks by viewing or altering logs.

17. SecurityEvents.ReadWrite.All

	•	Description: Allows the app to read and write all security events in the tenant.
	•	Risk: The app can modify security-related data, which might be used to disable alerts or hide malicious activities.

18. Reports.Read.All

	•	Description: Allows the app to read all usage reports in the tenant.
	•	Risk: The app can access usage reports, which might include sensitive information about user activity and resource usage.

19. IdentityRiskEvent.ReadWrite.All

	•	Description: Allows the app to read and write all identity risk event data.
	•	Risk: The app can modify identity risk events, potentially hiding signs of account compromise or other security issues.

20. Policy.ReadWrite.ApplicationConfiguration

	•	Description: Allows the app to read and write application configuration policies.
	•	Risk: The app can modify policies that affect how applications operate within the tenant, potentially weakening security controls.


