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

def get_all_users(access_token):
    """Retrieve all users from Microsoft 365 with pagination."""
    users = []
    endpoint = "https://graph.microsoft.com/v1.0/users"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    while endpoint:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()
            users.extend(data.get('value', []))
            endpoint = data.get('@odata.nextLink')
        else:
            print(f"Error retrieving users: {response.status_code} - {response.text}")
            break
    
    return users

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
    
    # Retrieve all users
    users = get_all_users(access_token)
    print(f"Total users retrieved: {len(users)}")
    for user in users:
        email = user.get('mail') or user.get('userPrincipalName')
        print(f"- {email}")

if __name__ == "__main__":
    main()
