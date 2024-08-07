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

def test_permission(access_token, endpoint):
    """Test if the current user has access to a specific endpoint."""
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    response = requests.get(endpoint, headers=headers)
    return response.status_code

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
    
    # Define a list of critical endpoints to test and their required permissions
    endpoints = {
        "User.Read": "https://graph.microsoft.com/v1.0/me",
        "User.ReadBasic.All": "https://graph.microsoft.com/v1.0/users",
        "Directory.Read.All": "https://graph.microsoft.com/v1.0/directoryRoles",
        "Mail.Read": "https://graph.microsoft.com/v1.0/me/messages",
        "Files.Read.All": "https://graph.microsoft.com/v1.0/me/drive/root/children",
        "Calendars.Read": "https://graph.microsoft.com/v1.0/me/events",
        "Contacts.Read": "https://graph.microsoft.com/v1.0/me/contacts",
        "Policy.Read.All": "https://graph.microsoft.com/v1.0/policies",
        "Group.Read.All": "https://graph.microsoft.com/v1.0/groups",
        "Application.Read.All": "https://graph.microsoft.com/v1.0/applications",
        "Reports.Read.All": "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='D7')",
        "IdentityRiskEvent.Read.All": "https://graph.microsoft.com/v1.0/identityProtection/riskEvents",
        # Additional endpoints
        "Security Alerts": "https://graph.microsoft.com/v1.0/security/alerts",
        "Risky Users": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers",
        "Managed Devices": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
        "Audit Logs": "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
        "Team Channels": "https://graph.microsoft.com/v1.0/teams/{team-id}/channels",  # Replace {team-id}
        "SharePoint Sites": "https://graph.microsoft.com/v1.0/sites",
        "Intune Device Configurations": "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"
    }
    
    # Test each endpoint
    print("Testing permissions:")
    for permission, endpoint in endpoints.items():
        status_code = test_permission(access_token, endpoint)
        if status_code == 200:
            print(f"- {permission}: Granted")
        elif status_code == 403:
            print(f"- {permission}: Forbidden")
        elif status_code == 401:
            print(f"- {permission}: Unauthorized")
        else:
            print(f"- {permission}: Unknown response (status code {status_code})")

if __name__ == "__main__":
    main()
