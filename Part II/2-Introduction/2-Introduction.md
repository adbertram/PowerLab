# Part II Introduction and Lab Setup

Requirements: 
 - Windows 10 Pro client (CLIENT)
 - Hyper-V Server with Windows Server 2012 R2 (HYPERVSRV)

## Lab setup

1. Enable RSAT on the client.

2. Run the PrerequisiteSetup.ps1 script on your client.

This will:
    - CLIENT:
        - Add HYPERVSRV ip address to hosts file
        - Add HYPERVSRV name to TrustedHosts
        - Add the ANONYMOUS LOGON user to the Distributed COM users group
        - Add necessary firewall rules
    - HYPERVSRV
        - Add CLIENT ip address to hosts file
        - Enable PowerShell remoting
        - Add necessary firewall rules
        - Add the ANONYMOUS LOGON user to the Distributed COM users group