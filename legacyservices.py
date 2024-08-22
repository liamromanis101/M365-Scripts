# Liam Romanis
# Alpha

import smtplib
import poplib
import imaplib
import getpass
import ssl
import requests
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree as ET

# Prompt for credentials
email = input("Enter your email address: ")
password = getpass.getpass("Enter your password: ")

# SMTP Server Configuration
smtp_server_ssl = "smtp.office365.com"
smtp_server_non_ssl = "smtp.office365.com"
smtp_port_ssl = 587
smtp_port_non_ssl = 25

# POP3 Server Configuration
pop3_server_ssl = "outlook.office365.com"
pop3_server_non_ssl = "outlook.office365.com"
pop3_port_ssl = 995
pop3_port_non_ssl = 110

# IMAP Server Configuration
imap_server_ssl = "outlook.office365.com"
imap_server_non_ssl = "outlook.office365.com"
imap_port_ssl = 993
imap_port_non_ssl = 143

# EWS Server Configuration
ews_url = 'https://outlook.office365.com/EWS/Exchange.asmx'

# ActiveSync Server Configuration
activesync_url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"

# RPC Over HTTP Server Configuration
rpc_url = "https://outlook.office365.com/rpc/rpcproxy.dll"

# MAPI Over HTTP Server Configuration
mapi_url = "https://outlook.office365.com/mapi/emsmdb/?MailboxId={mailbox_id}"

# AutoDiscover Server Configuration
autodiscover_url = "https://outlook.office365.com/autodiscover/autodiscover.xml"

# Remote Powershell Server Configuration
rpowershell_url = "https://outlook.office365.com/powershell-liveid"


# Function to test SMTP authentication
def smtp_login(use_ssl=True):
    server_type = "SMTP (SSL)" if use_ssl else "SMTP (Non-SSL)"
    server = None
    
    try:
        if use_ssl:
            server = smtplib.SMTP(smtp_server_ssl, smtp_port_ssl)
        else:
            server = smtplib.SMTP(smtp_server_non_ssl, smtp_port_non_ssl)
        
        server.starttls(context=ssl.create_default_context())  # Secure the connection
        
        server.login(email, password)
        print(f"{server_type} login successful")
        server.quit()
    
    except smtplib.SMTPAuthenticationError as auth_error:
        # Specific handling for authentication errors
        error_code = auth_error.smtp_code
        error_message = auth_error.smtp_error.decode('utf-8')
        
        if error_code == 535 and "5.7.3 Authentication unsuccessful" in error_message:
            print(f"{server_type} login failed: MFA might be required (Error {error_code})")
        elif error_code == 535 and "5.7.139 Authentication unsuccessful, MFA required" in error_message:
            print(f"{server_type} login failed: MFA is required (Error {error_code})")
        elif error_code == 535 and "5.7.8 Authentication failed, another step is needed in authentication" in error_message:
            print(f"{server_type} login failed: Legacy authentication blocked, MFA required (Error {error_code})")
        elif error_code == 535 and "5.7.3 Authentication unsuccessful, SMTP client authentication is disabled" in error_message:
            print(f"{server_type} login failed: SMTP client authentication is disabled (Error {error_code})")
        elif error_code == 535 and "5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant" in error_message:
        	print(f"{server_type} login failed: SmtpClientAuthentication is disabled (Error {error_code})")
        else:
            print(f"{server_type} login failed: Authentication failed (Error {error_code}): {error_message}")
    
    except smtplib.SMTPException as e:
        # General SMTP errors
        print(f"{server_type} login failed: SMTP error occurred: {e}")
    
    except Exception as e:
        # Catch-all for other errors
        print(f"{server_type} login failed: An unexpected error occurred: {e}")

# Function to test POP3 authentication
def pop3_login(use_ssl=True):
    server_type = "POP3 (SSL)" if use_ssl else "POP3 (Non-SSL)"
    server = None
    
    try:
        if use_ssl:
            server = poplib.POP3_SSL(pop3_server_ssl, pop3_port_ssl)
        else:
            server = poplib.POP3(pop3_server_non_ssl, pop3_port_non_ssl)
        
        server.user(email)
        server.pass_(password)
        print(f"{server_type} login successful")
        server.quit()
    
    except poplib.error_proto as e:
        error_message = str(e)
        
        if "authentication failed" in error_message.lower():
            print(f"{server_type} login failed: Authentication failed. MFA might be required or credentials are incorrect.")
        elif "logon failure" in error_message.lower():
            print(f"{server_type} login failed: Logon failure. MFA might be required or basic authentication is disabled.")
        elif "not authorized" in error_message.lower():
            print(f"{server_type} login failed: User is not authorized to log in. Basic authentication might be disabled.")
        elif "account is locked" in error_message.lower():
            print(f"{server_type} login failed: User account is locked.")
        elif "application-specific password required" in error_message.lower():
            print(f"{server_type} login failed: Application-specific password required. Basic authentication might be disabled.")
        elif "username and password not accepted" in error_message.lower():
            print(f"{server_type} login failed: Username and password not accepted. Basic authentication is likely disabled.")
        elif "login failed" in error_message.lower():
            print("POP3 service not available")
        else:
            print(f"{server_type} login failed: An unexpected error occurred: {error_message}")
    
    except Exception as e:
        print(f"{server_type} login failed: An unexpected error occurred: {e}")

 # Function to test IMAP authentication   
def imap_login(use_ssl=True):
    server_type = "IMAP (SSL)" if use_ssl else "IMAP (Non-SSL)"
    server = None
    
    try:
        if use_ssl:
            server = imaplib.IMAP4_SSL(imap_server_ssl, imap_port_ssl)
        else:
            server = imaplib.IMAP4(imap_server_non_ssl, imap_port_non_ssl)
        
        server.login(email, password)
        print(f"{server_type} login successful")
        server.logout()
    
    except imaplib.IMAP4.error as e:
        error_message = str(e)
        
        if "authentication failed" in error_message.lower():
            print(f"{server_type} login failed: Authentication failed. MFA might be required or credentials are incorrect.")
        elif "account is locked" in error_message.lower():
            print(f"{server_type} login failed: Account is locked, potentially due to MFA or security policies.")
        elif "application-specific password required" in error_message.lower():
            print(f"{server_type} login failed: Application-specific password required. Basic authentication might be disabled.")
        elif "username and password not accepted" in error_message.lower():
            print(f"{server_type} login failed: Username and password not accepted. Basic authentication is likely disabled.")
        elif "aadsts50076" in error_message.lower():
            print(f"{server_type} login failed: MFA is required to access this account.")
        elif "login failed:" in error_message.lower():
        	print("f{server_type} login failed: Service not available")
        else:
            print(f"{server_type} login failed: An unexpected error occurred: {error_message}")
    except Exception as e:
        print(f"{server_type} login failed: An unexpected error occurred: {e}")



# Function to test EWS authentication
def test_ews_authentication():

    
    # Example SOAP request to GetFolder operation
    soap_request = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <m:GetFolder xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                     xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
          <m:FolderShape>
            <t:BaseShape>Default</t:BaseShape>
          </m:FolderShape>
          <m:FolderIds>
            <t:DistinguishedFolderId Id="inbox"/>
          </m:FolderIds>
        </m:GetFolder>
      </soap:Body>
    </soap:Envelope>'''

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'http://schemas.microsoft.com/exchange/services/2006/messages/GetFolder'
    }

    try:
        response = requests.post(
            ews_url,
            data=soap_request,
            headers=headers,
            auth=HTTPBasicAuth(email, password),
            timeout=10
        )

        if response.status_code == 401:
            if 'Basic' in response.headers.get('WWW-Authenticate', ''):
                print("Error: Basic authentication is disabled for this tenant.")
            elif 'Bearer' in response.headers.get('WWW-Authenticate', ''):
                print("Error: Modern authentication (OAuth 2.0) is required. Basic authentication is not supported.")
            else:
                print("Error: Authentication failed. Please check your credentials.")
        elif response.status_code == 403:
            if 'AADSTS50076' in response.text:
                print("Error: Multi-Factor Authentication (MFA) is required.")
            elif 'AADSTS53003' in response.text:
                print("Error: Conditional Access policies are blocking access.")
            else:
                print("Error: Access is forbidden. Check if you have the necessary permissions.")
        else:
            print("Response Code:", response.status_code)
            print("Response Content:", response.text)

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


def test_activesync_login():
    try:
        response = requests.get(activesync_url, auth=HTTPBasicAuth(email, password))
        
        if response.status_code == 200:
            print("ActiveSync login successful.")
        elif response.status_code == 401:
            print("Login failed: Unauthorized. Check credentials or MFA might be required.")
        elif response.status_code == 403:
            print("Login failed: Forbidden. Check permissions or conditional access policies.")
        elif response.status_code == 500:
            print("Login failed: Internal Server Error. Possible server-side issue.")
        elif response.status_code == 451:
            print("Login failed: Temporary Server Error. Try again later.")
        elif response.status_code == 404:
            print("Login failed: Not Found. Check the ActiveSync URL or user provisioning.")
        else:
            print(f"Login failed: Unexpected error (status code: {response.status_code}). Response: {response.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"Login failed: Network error or other exception: {e}")


def test_rpc_over_http_login():
    try:
        # Initiating a POST request to simulate an RPC over HTTP login attempt
        response = requests.post(rpc_url, auth=HTTPBasicAuth(email, password))
        
        if response.status_code == 200:
            print("RPC over HTTP login successful.")
        elif response.status_code == 401:
            print("Login failed: Unauthorized. Check credentials or MFA might be required.")
        elif response.status_code == 403:
            print("Login failed: Forbidden. Check permissions or conditional access policies.")
        elif response.status_code == 404:
            print("Login failed: Not Found. Check the RPC over HTTP endpoint or user provisioning.")
        elif response.status_code == 500:
            print("Login failed: Internal Server Error. Possible server-side issue.")
        elif response.status_code == 501:
            print("Login failed: Not Implemented. The server may not support RPC over HTTP.")
        elif response.status_code == 503:
            print("Login failed: Service Unavailable. The service may be down or overloaded.")
        else:
            print(f"Login failed: Unexpected error (status code: {response.status_code}). Response: {response.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"Login failed: Network error or other exception: {e}")


def test_mapi_over_http_login():
    try:
        # Simulating an MAPI over HTTP login attempt
        response = requests.get(mapi_url.format(mailbox_id=email), auth=HTTPBasicAuth(email, password))
        
        if response.status_code == 200:
            print("MAPI over HTTP login successful.")
        elif response.status_code == 401:
            print("Login failed: Unauthorized. Check credentials, or MFA might be required, or Basic Auth might be disabled.")
        elif response.status_code == 403:
            print("Login failed: Forbidden. Check permissions, or access might be blocked by conditional access policies.")
        elif response.status_code == 404:
            print("Login failed: Not Found. Check the MAPI over HTTP endpoint or user provisioning.")
        elif response.status_code == 500:
            print("Login failed: Internal Server Error. Possible server-side issue.")
        elif response.status_code == 501:
            print("Login failed: Not Implemented. MAPI over HTTP might not be supported or enabled.")
        elif response.status_code == 503:
            print("Login failed: Service Unavailable. The service may be down or overloaded.")
        else:
            print(f"Login failed: Unexpected error (status code: {response.status_code}). Response: {response.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"Login failed: Network error or other exception: {e}")


def test_autodiscover_login():
    """Test AutoDiscover login and handle common errors."""
    headers = {
        'Content-Type': 'text/xml',
        'User-Agent': 'Python/3.8'
    }
    payload = """<?xml version="1.0" encoding="utf-8"?>
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
      <Request>
        <EMailAddress>{}</EMailAddress>
      </Request>
    </Autodiscover>""".format(email)

    try:
        response = requests.post(autodiscover_url, data=payload, headers=headers, auth=HTTPBasicAuth(email, password))
        
        if response.status_code == 200:
            print("AutoDiscover login successful")
        elif response.status_code == 401:
            print("401 Unauthorized - Invalid credentials or Basic Authentication might be disabled")
        elif response.status_code == 403:
            print("403 Forbidden - Access denied due to permissions or policies")
        elif response.status_code == 400:
            print("400 Bad Request - Malformed request or invalid endpoint")
        elif response.status_code in [502, 503]:
            print("502/503 Bad Gateway/Service Unavailable - Server issues or service unavailability")
        elif response.status_code in [500]:
            print("500 Error, Server issues. ")
        else:
            print(f"Unexpected response code: {response.status_code} - {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")




def test_powershell_endpoint(url, email, password):
    """Test various Remote PowerShell endpoints and handle common errors."""
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Python/3.8'
    }
    payload = {
        'username': email,
        'password': password
    }

    try:
        response = requests.post(url, data=payload, headers=headers, auth=HTTPBasicAuth(email, password))
        
        if response.status_code == 200:
            print(f"Login successful for {url}")
        elif response.status_code == 401:
            print(f"401 Unauthorized - Invalid credentials or Basic Authentication might be disabled for {url}")
        elif response.status_code == 403:
            print(f"403 Forbidden - Access denied due to permissions or Conditional Access policies for {url}")
        elif response.status_code == 400:
            print(f"400 Bad Request - Malformed request or invalid endpoint for {url}")
        elif response.status_code == 405:
            print(f"405 Method Not Allowed - HTTP method not supported by the endpoint for {url}")
        elif response.status_code == 503:
            print(f"503 Service Unavailable - Endpoint down or service issue for {url}")
        elif response.status_code == 426:
            print(f"426 Upgrade Required - Endpoint requires modern authentication for {url}")
        elif response.status_code == 500:
            print(f"500 Internal Server Error - Server Not Available for {url}")
            #print(f"Response text: {response.text}")
        else:
            print(f"Unexpected response code for {url}: {response.status_code} - {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {url}: {e}")



if __name__ == "__main__":
    print("Testing SMTP logins...")
    smtp_login(use_ssl=True)
    smtp_login(use_ssl=False)

    print("\nTesting POP3 logins...")
    pop3_login(use_ssl=True)
    pop3_login(use_ssl=False)

    print("\nTesting IMAP logins...")
    imap_login(use_ssl=True)
    imap_login(use_ssl=False)

    print("\nTesting EWS Login...")
    test_ews_authentication()
    
    print("\nTesting ActiveSync Login")
    test_activesync_login()
    
    print("\nTesting RPC Over HTTP Login")
    test_rpc_over_http_login()
    
    print("\nTesting MAPI Over HTTP Login")
    test_mapi_over_http_login()
    
    print("\nTesting AutoDiscover Login")
    test_autodiscover_login()
    
    print("\nTesting Remote Powershell EndPoints")
    
    endpoints = {
        "Exchange Online PowerShell": "https://outlook.office365.com/powershell-liveid",
        "Microsoft Teams": "https://ps.teams.microsoft.com/",
        "Microsoft Graph API": "https://graph.microsoft.com/v1.0/",
        "Skype for Business Online": "https://adminskype.microsoftonline.com/",
        "Security & Compliance Center (SCC) PowerShell": "https://ps.compliance.protection.outlook.com/powershell-liveid",
        "Outlook Remote PowerShell": "https://ps.outlook.com/PowerShell-LiveID",
        "PowerBI API":"https://api.powerbi.com",
        "OutLook REST API":"https://outlook.office.com/api/v2.0/",
        "One Drive REST API":"https://graph.microsoft.com/v1.0/me/drive",
        "Yammer REST API":"https://www.yammer.com/api/v1/"     
        }

    for name, url in endpoints.items():
        print(f"\nTesting {name} Login")
        test_powershell_endpoint(url, email, password)
    
    
