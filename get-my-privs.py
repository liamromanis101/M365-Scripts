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

def get_user_roles(user_id, access_token):
    """Get roles assigned to the current user."""
    endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}/appRoleAssignments"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error retrieving user roles: {response.status_code} - {response.text}")
        return []

def get_user_groups(user_id, access_token):
    """Get groups the current user belongs to."""
    endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error retrieving user groups: {response.status_code} - {response.text}")
        return []

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
        
        # Get and print user roles
        roles = get_user_roles(user_id, access_token)
        print("User Roles:")
        for role in roles:
            print(f"- {role['resourceDisplayName']}: {role['appRoleId']}")
        
        # Get and print user groups
        groups = get_user_groups(user_id, access_token)
        print("User Groups:")
        for group in groups:
            print(f"- {group['displayName']} ({group['id']})")
    
    else:
        print("Failed to retrieve user details.")

if __name__ == "__main__":
    main()
