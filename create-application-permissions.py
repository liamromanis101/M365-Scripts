import subprocess
import json
import requests

def run_command(command):
    """Run a command and return its output."""
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {result.stderr}")
    return result.stdout.strip()

def login_azure():
    """Perform az login using --allow-no-subscriptions."""
    print("Logging in to Azure...")
    run_command("az login --allow-no-subscriptions")

def list_available_tenants():
    """List available tenants and prompt user to select one."""
    tenants_output = run_command("az account list --all --query '[].{Name:name, TenantId:tenantId}' --output json")
    tenants = json.loads(tenants_output)
    
    if not tenants:
        raise RuntimeError("No tenants found.")
    
    print("Available tenants:")
    for idx, tenant in enumerate(tenants):
        print(f"{idx + 1}: {tenant['Name']} (Tenant ID: {tenant['TenantId']})")
    
    choice = int(input("Enter the number of the tenant you want to use: ")) - 1
    if choice < 0 or choice >= len(tenants):
        raise ValueError("Invalid choice.")
    
    return tenants[choice]['TenantId']

def get_access_token(resource):
    """Get an access token for the specified resource."""
    token_response = run_command(f"az account get-access-token --resource {resource}")
    token_data = json.loads(token_response)
    return token_data['accessToken']

def get_current_user(access_token):
    """Get details of the current user."""
    endpoint = "https://graph.microsoft.com/v1.0/me"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error retrieving user details: {response.status_code} - {response.text}")
        return None



# Step 4: Check if the user can create new applications
def check_application_creation_permission(access_token):
    perms = False
    print("Checking application creation permissions...")
    url = "https://graph.microsoft.com/v1.0/me"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print("Failed to retrieve user information:", response.text)
        exit(1)
    
    user_info = response.json()
    print(f"User: {user_info['displayName']} ({user_info['userPrincipalName']})")
        
    # Check if user can create applications
    url = "https://graph.microsoft.com/v1.0/applications"
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        print("[-] User does not have permission to create applications.")
    elif response.status_code == 200:
        print("[+] User has permission to create applications.")
        perms = True
    else:
        print("[!] Unexpected response:", response.status_code, response.text)

    return perms
    
    
    
    
    # Step 5: Check for conditional access policies
def check_conditional_access_policies(access_token):
    print("Checking for conditional access policies...")
    url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        print("[-] User does not have permission to access conditional access policies.")
    elif response.status_code == 200:
        policies = response.json()
        if len(policies.get('value', [])) == 0:
            print("[!] No conditional access policies found.")
        else:
            print(f"[+] Found {len(policies['value'])} conditional access policy/policies:")
            for policy in policies['value']:
                print(f"[+] - {policy['displayName']}: {policy['state']}")
    else:
        print("[!] Unexpected response:", response.status_code, response.text)

# Step 6: Check user consent settings
def check_user_consent_settings(access_token):
    print("Checking user consent settings...")
    
    # Correct endpoint for authorization policy
    url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Perform the request
    response = requests.get(url, headers=headers)
    
    if response.status_code == 403:
        print("[-] User does not have permission to access authorization policies.")
    elif response.status_code == 200:
        policies = response.json().get('value', [])
        if len(policies) == 0:
            print("[!] No authorization policies found.")
        else:
            for policy in policies:
                user_consent_enabled = policy.get("defaultUserRolePermissions", {}).get("userConsentToAppEnabled", False)
                if user_consent_enabled:
                    print("[+] User consent to applications is enabled.")
                else:
                    print("[-] User consent to applications is disabled.")
    else:
        print(f"[!] Unexpected response: {response.status_code} {response.text}")

# Step 7: Check if admin consent workflow is enabled
def check_admin_consent_workflow(access_token):
    print("Checking if admin consent workflow is enabled...")
    
    # Endpoint to check admin consent requests and policies
    url = "https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Perform the request
    response = requests.get(url, headers=headers)
    
    if response.status_code == 403:
        print("[-] User does not have permission to access app consent requests.")
    elif response.status_code == 200:
        app_consent_requests = response.json().get('value', [])
        if len(app_consent_requests) == 0:
            print("[!] No admin consent workflows found.")
        else:
            print(f"[+] Found {len(app_consent_requests)} admin consent request(s):")
            for request in app_consent_requests:
                print(f"[+] - Request ID: {request['id']}, Status: {request['status']}, App Display Name: {request['appDisplayName']}")
    else:
        print(f"[!] Unexpected response: {response.status_code} {response.text}")

# Step 8: Check if user can grant consent with reduced permissions
def check_reduced_permissions_consent(access_token):
    print("Checking if user can grant consent with reduced permissions...")
    # Attempt to list service principals to determine if user can grant reduced permissions
    url = "https://graph.microsoft.com/v1.0/servicePrincipals"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        print("[-] User cannot grant consent with reduced permissions.")
    elif response.status_code == 200:
        print("[+] User can grant consent with reduced permissions.")
    else:
        print("[!] Unexpected response:", response.status_code, response.text)
        
        
        
# Get APP ID for valid application
def get_app_id_by_name(access_token, app_name):
    print(f"Searching for app with name: {app_name}...")
    
    # Endpoint to search for applications by display name
    url = "https://graph.microsoft.com/v1.0/applications"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    params = {
        "$filter": f"displayName eq '{app_name}'"
    }
    
    # Perform the request
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        apps = response.json().get('value', [])
        if len(apps) == 0:
            print(f"[!] No application found with the name '{app_name}'.")
            return None
        elif len(apps) == 1:
            app_id = apps[0]['appId']
            print(f"[+] Found application '{app_name}' with App ID: {app_id}")
            return app_id
        else:
            print(f"[!] Multiple applications found with the name '{app_name}'. Please refine your search.")
            for app in apps:
                print(f"[+] - App ID: {app['appId']}, Display Name: {app['displayName']}")
            return None
    else:
        print(f"[!] Error retrieving app ID: {response.status_code} {response.text}")
        return None
        
        
        
        
# Step 10: function to check admin consent capability
def check_admin_consent_capability(access_token, app_id):
    print("Checking if admin consent can be granted with elevated permissions...")
    
    # Endpoint to grant admin consent for a specific application
    url = f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Payload to attempt admin consent for an application
    payload = {
        "clientId": app_id,  # Application ID for which you want to check consent
        "consentType": "AllPrincipals",
        "principalId": None,
        "resourceId": app_id,
        "scope": "User.Read",  # Example scope, adjust as needed
        "startDateTime": "2024-08-12T00:00:00Z",
        "expiryDateTime": "2025-08-12T00:00:00Z"
    }
    
    # Perform the request to grant admin consent
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 201:
        print("[+] Admin consent was successfully granted.")
    elif response.status_code == 403:
        print("[-] User does not have permission to grant admin consent.")
    elif response.status_code == 400:
        print("[!] Bad request. This might be due to invalid payload or insufficient permissions.")
    else:
        print(f"[!] Unexpected response: {response.status_code} {response.text}")


def main():
    # Perform az login
    login_azure()
    
    # List available tenants and let the user choose one
    tenant_id = list_available_tenants()
    print(f"Selected Tenant ID: {tenant_id}")
    
    # Set the tenant for the current session
    run_command(f"az account set --subscription {tenant_id}")
    
    # Get Access Token for Microsoft Graph API
    access_token = get_access_token("https://graph.microsoft.com")
    
    # Get current user details
    user_details = get_current_user(access_token)
    if user_details:
        user_id = user_details['id']
        user_mail = user_details.get('mail', 'No email address found')
        print(f"User ID: {user_id}")
        print(f"User Email: {user_mail}")
        
        perms = check_application_creation_permission(access_token)
        if perms:
            check_conditional_access_policies(access_token)
            check_user_consent_settings(access_token)
            check_admin_consent_workflow(access_token)
            check_reduced_permissions_consent(access_token)
            print("Testing Admin Consent Capability: We will need a valid app name")
            app_name = input("Enter the application name: ")
            app_id = get_app_id_by_name(access_token, app_name)

            if app_id:
                # You can now use the app_id for further operations
                print(f"App ID for '{app_name}' is: {app_id}")
                check_admin_consent_capability(access_token, app_id)
    else:
        print("Failed to retrieve user details.")

if __name__ == "__main__":
    main()
