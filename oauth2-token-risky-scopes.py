import os
import subprocess
import json
import requests

# Step 1: Authenticate using Azure CLI
def az_login():
    print("Authenticating via Azure CLI...")
    result = subprocess.run(["az", "login", "--allow-no-subscriptions"], capture_output=True, text=True)
    if result.returncode != 0:
        print("Failed to authenticate.")
        print(result.stderr)
        return None
    return json.loads(result.stdout)

# Step 2: List available tenants
def list_tenants():
    print("Fetching available tenants...")
    result = subprocess.run(["az", "account", "list", "--all", "--output", "json"], capture_output=True, text=True)
    if result.returncode != 0:
        print("Failed to list tenants.")
        print(result.stderr)
        return None
    tenants = json.loads(result.stdout)
    return tenants

# Step 3: Select a tenant for testing
def select_tenant(tenants):
    print("\nAvailable Tenants:")
    for i, tenant in enumerate(tenants):
        print(f"{i + 1}: {tenant['tenantId']} ({tenant.get('name', 'No Name')})")
    
    selected = int(input("Select a tenant by number: ")) - 1
    return tenants[selected]['tenantId']

# Step 4: Query Microsoft Graph API for Service Principals
def get_service_principals(access_token, tenant_id):
    print("Getting Service Principals")
    url = f"https://graph.microsoft.com/v1.0/{tenant_id}/servicePrincipals"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print("Failed to fetch service principals.")
        print(response.text)
        return None
    return response.json()

# Step 5: Query OAuth2 Permission Grants for each Service Principal
def get_oauth2_permissions(access_token, tenant_id, service_principal_id):
    url = f"https://graph.microsoft.com/v1.0/{tenant_id}/oauth2PermissionGrants"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    params = {
        "$filter": f"clientId eq '{service_principal_id}'"
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Failed to fetch OAuth2 permissions for service principal {service_principal_id}.")
        print(response.text)
        return None
    return response.json()



# Step 6: Analyze Permissions for Potential Risks and Check for Duplicate Names
def analyze_permissions(service_principals, permissions):
    risky_scopes = [
        'full_access_as_user', 'User.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send',
        'Files.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.ReadWrite.All',
        'Calendars.ReadWrite', 'Contacts.ReadWrite', 'Notes.ReadWrite.All',
        'Tasks.ReadWrite', 'People.ReadWrite', 'DeviceManagementApps.ReadWrite.All',
        'Sites.FullControl.All', 'TeamSettings.ReadWrite.All', 'AuditLog.Read.All',
        'SecurityEvents.ReadWrite.All', 'Reports.Read.All', 'IdentityRiskEvent.ReadWrite.All',
        'Policy.ReadWrite.ApplicationConfiguration'
    ]
    
    print("\nAnalyzing OAuth2 Permissions and Checking for Duplicate Names...")
    risky_apps = {}
    app_names = {}
    
    for sp in service_principals['value']:
        sp_id = sp['id']
        sp_name = sp['displayName']
        sp_permissions = permissions.get(sp_id, [])
        
        # Check for duplicate names
        if sp_name in app_names:
            app_names[sp_name].append(sp_id)
        else:
            app_names[sp_name] = [sp_id]
        
        # Consolidate permissions for each application
        for perm in sp_permissions:
            for scope in risky_scopes:
                if scope in perm['scope']:
                    if sp_id in risky_apps:
                        risky_apps[sp_id]['scopes'].add(scope)
                    else:
                        risky_apps[sp_id] = {
                            'name': sp_name,
                            'scopes': {scope}
                        }

    # Report duplicate application names
    duplicates = {name: ids for name, ids in app_names.items() if len(ids) > 1}
    if duplicates:
        print("\nDuplicate Application Names Detected:")
        for name, ids in duplicates.items():
            print(f" - Application Name: {name}, App IDs: {', '.join(ids)}")
    
    if risky_apps:
        print("\nPotentially Risky Applications Detected:")
        for app_id, app_info in risky_apps.items():
            scopes_str = " ".join(app_info['scopes'])
            print(f" - Application: {app_info['name']} (App ID: {app_id}), Scope: {scopes_str}")
    else:
        print("\nNo overly permissive applications found.")




# Main script execution
if __name__ == "__main__":
    login_result = az_login()
    if login_result is None:
        exit(1)

    tenants = list_tenants()
    if tenants is None or len(tenants) == 0:
        print("No tenants available.")
        exit(1)

    tenant_id = select_tenant(tenants)

    # Extract access token from Azure CLI cache
    token_result = subprocess.run(["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com"], capture_output=True, text=True)
    if token_result.returncode != 0:
        print("Failed to get access token.")
        print(token_result.stderr)
        exit(1)

    access_token = json.loads(token_result.stdout)['accessToken']

    # Step 4: Get Service Principals
    service_principals = get_service_principals(access_token, tenant_id)
    if service_principals is None:
        exit(1)

    # Step 5: Get OAuth2 Permissions
    permissions = {}
    print("Getting OAuth2 Permission Grants for each Service Principal")
    for sp in service_principals['value']:
        sp_id = sp['id']
        sp_permissions = get_oauth2_permissions(access_token, tenant_id, sp_id)
        if sp_permissions:
            permissions[sp_id] = sp_permissions['value']

    # Step 6: Analyze Permissions
    analyze_permissions(service_principals, permissions)
