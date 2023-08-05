<#
PowerShell Script for Active Directory Enumeration and Hunting
Artwork:
          ____                                 ___                        ,----..
        ,'  , `.                             ,--.'|_                     /   /   \
     ,-+-,.' _ |                     .---.   |  | :,'           .---.   /   .     :
  ,-+-. ;   , ||                    /. ./|   :  : ' :          /. ./|  .   /   ;.  \
 ,--.'|'   |  ||    ,---.        .-'-. ' | .;__,'  /        .-'-. ' | .   ;   /  ` ;
|   |  ,', |  |,   /     \      /___/ \: | |  |   |        /___/ \: | ;   |  ; \ ; |
|   | /  | |--'   /    /  |  .-'.. '   ' . :__,'| :     .-'.. '   ' . |   :  | ; | '
|   : |  | ,     .    ' / | /___/ \:     '   '  : |__  /___/ \:     ' .   |  ' ' ' :
|   : |  |/      '   ;   /| .   \  ' .\      |  | '.'| .   \  ' .\    '   ;  \; /  |
|   | |`-'       '   |  / |  \   \   ' \ |   ;  :    ;  \   \   ' \ |  \   \  ',  /
|   ;/           |   :    |   \   \  |--"    |  ,   /    \   \  |--"    ;   :    /
'---'             \   \  /     \   \ |        ---`-'      \   \ |        \   \ .'
#>

# Prompt for domain name
$domainName = Read-Host "Enter the domain name:"

# Prompt for username
$username = Read-Host "Enter the username:"

# Prompt for password (masked input)
$securePassword = Read-Host "Enter the password:" -AsSecureString
$credentials = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

try {
    # Generic AD info
    Write-Output "===== Generic AD info ====="
    $env:USERDOMAIN # Get domain name
    $env:USERDNSDOMAIN # Get domain name
    $env:logonserver # Get name of the domain controller
    Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty DNSHostName # Get name of the domain controller
    (Get-WmiObject Win32_ComputerSystem).Name # Get name of the domain controller
    gpresult /V # Get current policy applied
    Get-WmiObject Win32_NTDomain | Format-List * # Displays information about the Domain and Domain Controllers

    # Users
    Write-Output "===== Users ====="
    dsquery user # Get all users
    net user /domain # List all users of the domain
    net user $username /domain # Get information about that user
    net accounts /domain # Password and lockout policy
    Get-WmiObject Win32_UserAccount | Format-List * # Displays information about all local accounts and any domain accounts that have logged into the device
    Get-WmiObject -Namespace "root\directory\ldap" -Class ds_user | Format-List * # Get all users
    $targetUser = Read-Host "Enter the username to get information about:"
    Get-WmiObject -Namespace "root\directory\ldap" -Query "SELECT * FROM ds_user WHERE ds_samaccountname='$targetUser'" | Format-List * # Get info of 1 user
    Get-WmiObject Win32_SystemAccount | Format-List * # Dumps information about any system accounts that are being used as service accounts.

    # Groups
    Write-Output "===== Groups ====="
    net group /domain # List of domain groups
    net localgroup administrators /domain # List users that belong to the administrators group inside the domain (the group "Domain Admins" is included here)
    net group "Domain Admins" /domain # List users with domain admin privileges
    net group "domain computers" /domain # List PCs connected to the domain
    Get-WmiObject Win32_Group | Format-List * # Information about all local groups
    Get-WmiObject -Namespace "root\directory\ldap" -Class ds_group | Format-List * # Get all groups
    $targetGroup = Read-Host "Enter the group name to get members:"
    Get-WmiObject -Namespace "root\directory\ldap" -Query "SELECT ds_member FROM ds_group WHERE ds_samaccountname='$targetGroup'" | Format-List * # Members of the group

    # Computers
    Write-Output "===== Computers ====="
    dsquery computer # Get all computers
    net view /domain # List of PCs of the domain
    nltest /dclist:$domainName # List domain controllers
    Get-WmiObject -Namespace "root\directory\ldap" -Class ds_computer | Format-List * # All computers
    Get-WmiObject -Namespace "root\directory\ldap" -Class ds_computer | Select-Object -ExpandProperty ds_dnshostname # All computers

    # Trust relations
    Write-Output "===== Trust relations ====="
    nltest /domain_trusts # Mapping of the trust relationships

    # Get all objects inside an OU
    Write-Output "===== Objects inside an OU ====="
    $ouName = Read-Host "Enter the OU name to get objects:"
    dsquery * "OU=$ouName,DC=$domainName"

    # Me
    Write-Output "===== Me ====="
    whoami /all # All info about me, take a look at the enabled tokens
    whoami /priv # Show only privileges

    # Local users
    Write-Output "===== Local users ====="
    net users # All users
    dir /b /ad "C:\Users"
    net user $username # Info about a user (me)
    net accounts # Information about password requirements
    Get-WmiObject Win32_UserAccount | Select-Object Domain, Name, SID
    $newUsername = Read-Host "Enter the username to create a new user:"
    $newPassword = Read-Host "Enter the password for the new user:" -AsSecureString
    net user $newUsername $newPassword /add # Create user

    # Other users logged
    Write-Output "===== Other users logged ====="
    qwinsta # Anyone else logged in?

    # Launch new cmd.exe with new creds
    Write-Output "===== Launch new cmd.exe with new creds ====="
    $newCred = Get-Credential -Message "Enter credentials to launch new cmd.exe"
    Start-Process cmd.exe -Credential $newCred

    # Local
    Write-Output "===== Local ====="
    net localgroup # All available groups
    net localgroup administrators # Info about a group (admins)
    $userToAdd = Read-Host "Enter the username to add to the administrators group:"
    net localgroup administrators $userToAdd /add # Add user to administrators

    # Domain
    Write-Output "===== Domain ====="
    net group /domain # Info about domain groups
    $domainGroup = Read-Host "Enter the domain group name to get members:"
    net group /domain $domainGroup # Users that belong to the group

    # Firewall and RDP
    Write-Output "===== Firewall and RDP ====="
    netsh advfirewall firewall show rule name=all # FW info, open ports
    netsh firewall show config # FW info
    Get-NetFirewallProfile | Format-List * # Firewall info
    Get-NetFirewallRule | Format-List * # Firewall rules

    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False # Turn Off
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True # Turn On
    netsh advfirewall set allprofiles state off # Turn Off

    # How to open ports
    Write-Output "===== How to open ports ====="
    New-NetFirewallRule -Name "NetBIOS UDP Port 138" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 138
    New-NetFirewallRule -Name "NetBIOS TCP Port 139" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 139
    New-NetFirewallRule -Name "Remote Desktop" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389

    # Enable Remote Desktop
    Write-Output "===== Enable Remote Desktop ====="
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    New-NetFirewallRule -Name "Remote Desktop" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389

    # Connect to RDP
    Write-Output "===== Connect to RDP ====="
    $targetIP = Read-Host "Enter the target IP address or hostname for RDP:"
    xfreerdp /u:$username /d:$domainName /p:$securePassword /v:$targetIP

    net view # Get a list of computers
    net view /all /domain $domainName # Shares on the domain
    $targetComputer = Read-Host "Enter the name of the computer to list shares:"
    net view \\$targetComputer /ALL # List shares of a computer
    net use x: \\$targetComputer\share # Mount the share locally
    net share # Check current shares

    reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s

    ipconfig /all

    arp -A

    enable-psremoting -force # This enables WinRM

    # Change NetworkConnection Category to Private
    # Requires -RunasAdministrator
    Write-Output "===== Change NetworkConnection Category to Private ====="
    Get-NetConnectionProfile |
        Where-Object { $_.NetworkCategory -ne 'Private' } |
        ForEach-Object {
            $_
            Set-NetConnectionProfile -NetworkCategory Private -Confirm -InterfaceIndex $_.InterfaceIndex
        }

    # Check Windows Defender status
    Write-Output "===== Check Windows Defender status ====="
    Get-MpComputerStatus
    Get-MpPreference | Select-Object Exclusion* | Format-List # Check exclusions
    # Disable Windows Defender
    Write-Output "===== Disable Windows Defender ====="
    Set-MpPreference -DisableRealtimeMonitoring $true
    # To completely disable Windows Defender on a computer, use the command:
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
    # Set exclusion path
    Write-Output "===== Set exclusion path ====="
    Set-MpPreference -ExclusionPath (Get-Location).Path -DisableRealtimeMonitoring
    Add-MpPreference -ExclusionPath (Get-Location).Path

    # Check exclusions configured via GPO
    Write-Output "===== Check exclusions configured via GPO ====="
    Parse-PolFile .\Registry.pol
}
catch {
    Write-Error "An error occurred: $_.Exception.Message"
}

# Add Mewtwo ASCII art below
@"
                                                                        
 |_          _.  |  ._    _   ._   _   ._           _        ._  |      
 |_)  \/    (_|  |  |_)  (/_  |   (/_  | |    |_|  (_|  |_|  |   |  |_| 
      /             |                               _|                  
"@
