# M365-Scripts
Collection of scripts for testing M365 subscriptions

Legacy Services:
(legacyservices.py)
Requires requests and msal
pip install msal requests

This script attempts to identify legacy services which have not been disabled by attempting to login to them with a M365 user account. The script also tries to 'guess' domains for SharePoint, SharePoint SOAP Service and ADFS from the email address used to login. 

Legacy Services do not support MFA and therefore APTs will attempt to brute force accounts using these services or access M365 using these services with previously discovered accounts. 
