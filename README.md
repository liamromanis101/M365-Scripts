# M365-Scripts
Collection of scripts for testing M365 subscriptions (& Azure). Most of these scripts assume that access has been gained with a low privilege user account or that you are performing testing as a typical user where you do not have access to powershell. These scripts are intended for educational purposes or for authorized security assessments. 

For a brief on common attack vectors, please see: https://github.com/liamromanis101/M365-Scripts/blob/main/VECTORS.txt

## Legacy Services:
(legacyservices.py) - [alpha, more functionality to be added]
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

## OAuth2 Token Theft - Malicious Application Consent Phishing
(oauth2-token-risky-scopes.py)
Requires os, subprocess, json, requests
[pip install os subprocess json requests]

This script analyzes OAuth2 permissions granted to applications within the tenant. The script helps identify potential risks associated with OAuth token theft by examining the permissions granted to applications, particularly those with overly permissive scopes.

For further information on overly permissive scope please see: https://github.com/liamromanis101/M365-Scripts/blob/main/SCOPES.md

(create-application-permissions.py)
Requires subprocess, json, requests
[pip install subprocess json requests]

This script determines whether the user account can create new applications. If new applications can be created the script attempts to discover what configuration aspects could block a threat actor performing a malicious application consent phishing attack. 
