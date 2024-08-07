import requests
import getpass
from requests.exceptions import RequestException
import socket

# Configuration settings
legacy_services = {
    'IMAP': 'https://outlook.office365.com/imap',
    'POP3': 'https://outlook.office365.com/pop',
    'SMTP': 'https://outlook.office365.com/smtp',
    'ActiveSync': 'https://outlook.office365.com/microsoft-server-activesync',
    'RPC over HTTP': 'https://outlook.office365.com/rpc',
    'MAPI over HTTP': 'https://outlook.office365.com/mapi',
    'Autodiscover': 'https://outlook.office365.com/autodiscover/autodiscover.xml',
    'Remote PowerShell': 'https://outlook.office365.com/powershell-liveid/',
    'EWS': 'https://outlook.office365.com/EWS/Exchange.asmx',
    'Skype for Business': 'https://lyncweb.{domain}/',
    'Office 365 Management API': 'https://manage.office.com/api/v1.0/{tenant_id}/',
    'Teams': 'https://teams.microsoft.com/',
    'Outlook REST API': 'https://outlook.office365.com/api/v2.0/me/',
    'Legacy Exchange ActiveSync': 'https://outlook.office365.com/Microsoft-Server-ActiveSync',
    'Legacy RPC over HTTP': 'https://outlook.office365.com/rpc',
}

# ADFS service is special as it uses the domain part of the email address
adfs_service_name = 'ADFS'
adfs_endpoint_template = 'https://{domain}/adfs/ls/'

# SharePoint specific endpoints
sharepoint_endpoints = [
    'https://{domain}.sharepoint.com/_layouts/15/sharepoint.aspx',
    'https://{domain}-my.sharepoint.com/_layouts/15/sharepoint.aspx'
]

# SharePoint SOAP service endpoint
sharepoint_soap_endpoint = 'https://{domain}/_vti_bin/Lists.asmx'

# SharePoint access indicators
access_indicators = [
    "sorry, you don't have access",
    "request access",
    "you need permission",
    "access denied",
    "permission required"
]

# Error message indicating the domain does not exist
non_existent_domain_message = "Failed to resolve"

# Prompt for credentials
username = input('Enter your username (email): ')
password = getpass.getpass('Enter your password: ')

def extract_domains_from_email(email):
    """Extract potential SharePoint domains from the provided email address."""
    domains = set()
    try:
        local_part, domain = email.split('@')
        if domain:
            parts = domain.split('.')
            if len(parts) > 1:
                base_domain = parts[0]
                tlds = parts[1:]
                
                # Add base domain
                domains.add(base_domain)
                
                # Add combinations of base domain and tlds
                for i in range(len(tlds)):
                    combined_domain = base_domain + ''.join(tlds[i:])
                    domains.add(combined_domain)
                    
                    # Add domain with specific TLDs stripped
                    if len(tlds) > 1:
                        combined_domain = base_domain + ''.join(tlds[:-1])
                        domains.add(combined_domain)
                        
                    # Handle cases like 'co.uk'
                    if len(tlds) > 1 and tlds[-2] == 'co':
                        combined_domain = base_domain + tlds[-2] + tlds[-1]
                        domains.add(combined_domain)
    except ValueError:
        print('Invalid email format.')
    return domains

def attempt_login(service_name, endpoint, username, password):
    try:
        response = requests.get(endpoint, auth=(username, password))
        if response.status_code == 200:
            print(f'{service_name}: Login successful, Service is available with no MFA required. ')
        elif response.status_code == 403:
            print(f'{service_name}: Access denied, Service is likely available with no MFA required, but we do not have access.')
        elif response.status_code == 404 and service_name == adfs_service_name:
            print(f'{service_name}: Domain does not exist (404 Not Found)')
        else:
            print(f'{service_name}: Login failed with status code: {response.status_code}')
    except RequestException as e:
        print(f'{service_name}: Error during login attempt: {e}')

def check_sharepoint_access(response_text):
    """Check if the SharePoint response indicates that the domain exists but access is restricted."""
    for indicator in access_indicators:
        if indicator.lower() in response_text.lower():
            return f'SharePoint site: Access restricted (message: {indicator})'
    return 'SharePoint site: Access failed (no specific access message)'

def test_sharepoint_domains(domains):
    for domain in domains:
        for endpoint in sharepoint_endpoints:
            url = endpoint.format(domain=domain)
            try:
                response = requests.get(url, auth=(username, password))
                if non_existent_domain_message.lower() in response.text.lower():
                    # Skip printing for domains that fail to resolve
                    continue
                if response.status_code == 200:
                    print(f'SharePoint site at {url}: Access successful, Service exists with no MFA required')
                elif response.status_code == 403:
                    print(f'SharePoint site at {url}: Access denied, Service likely exists with no MFA required, but we do not have access. ')
                else:
                    access_message = check_sharepoint_access(response.text)
                    print(f'{url}: {access_message}')
            except RequestException as e:
                if isinstance(e, (socket.gaierror, socket.herror, socket.timeout)) or 'Failed to resolve' in str(e):
                    print(f'SharePoint site at {url}: Domain does not exist (NameResolutionError)')
                else:
                    print(f'SharePoint site at {url}: Error during access attempt: {e}')

def test_sharepoint_soap(domain):
    url = sharepoint_soap_endpoint.format(domain=domain)
    try:
        response = requests.get(url, auth=(username, password))
        if non_existent_domain_message.lower() in response.text.lower():
            print(f'SharePoint SOAP service at {url}: Domain does not exist (NameResolutionError)')
        elif response.status_code == 200:
            print(f'SharePoint SOAP service at {url}: Access successful, service exists with no MFA required. ')
        elif response.status_code == 403:
            print(f'SharePoint SOAP service at {url}: Access denied, service likely exists with no MFA, but we do not have access. ')
        else:
            access_message = check_sharepoint_access(response.text)
            print(f'{url}: {access_message}')
    except RequestException as e:
        if isinstance(e, (socket.gaierror, socket.herror, socket.timeout)) or 'Failed to resolve' in str(e):
            print(f'SharePoint SOAP service at {url}: Domain does not exist (NameResolutionError)')
        else:
            print(f'SharePoint SOAP service at {url}: Error during access attempt: {e}')

# Extract potential domains from email address
potential_domains = extract_domains_from_email(username)

# Extract the ADFS domain from the email address
try:
    _, adfs_domain = username.split('@')
    adfs_endpoint = adfs_endpoint_template.format(domain=adfs_domain)
    # Attempt login for ADFS
    attempt_login(adfs_service_name, adfs_endpoint, username, password)
except ValueError:
    print('Invalid email format for ADFS domain extraction.')

# Iterate over the legacy services (excluding ADFS)
for service_name, endpoint in legacy_services.items():
    if service_name != adfs_service_name:
        attempt_login(service_name, endpoint, username, password)

# Test SharePoint domains
if potential_domains:
    print(f'Testing potential SharePoint domains: {potential_domains}')
    test_sharepoint_domains(potential_domains)
    
    # Assume the SharePoint SOAP service uses the first domain from potential domains
    _, spsoap_domain = username.split('@')
    test_sharepoint_soap(spsoap_domain)
else:
    print('No SharePoint domains were found from the email address.')
