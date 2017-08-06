
[CmdletBinding()]
param
(

)
begin
{
	$ErrorActionPreference = 'Stop'
	
	function Test-PsRemoting
	{
		param (
			[Parameter(Mandatory = $true)]
			$computername,
			
			[Parameter(Mandatory)]
			[ValidateNotNullOrEmpty()]
			[pscredential]$Credential
			
		)
		
		try
		{
			$errorActionPreference = "Stop"
			$result = Invoke-Command -ComputerName $computername { 1 } -Credential $Credential
		}
		catch
		{
			return $false
		}
		
		## I�ve never seen this happen, but if you want to be
		## thorough�.
		if ($result -ne 1)
		{
			Write-Verbose "Remoting to $computerName returned an unexpected result."
			return $false
		}
		$true
	}
	
	function Add-TrustedHostComputer
	{
		[CmdletBinding()]
		param
		(
			[Parameter()]
			[ValidateNotNullOrEmpty()]
			[string[]]$ComputerName
			
		)
		try
		{
			foreach ($c in $ComputerName)
			{
				Write-Verbose -Message "Adding [$($c)] to client WSMAN trusted hosts"
				$TrustedHosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value
				if (-not $TrustedHosts)
				{
					Set-Item -Path wsman:\localhost\Client\TrustedHosts -Value $c -Force
				}
				elseif (($TrustedHosts -split ',') -notcontains $c)
				{
					$TrustedHosts = ($TrustedHosts -split ',') + $c
					Set-Item -Path wsman:\localhost\Client\TrustedHosts -Value ($TrustedHosts -join ',') -Force
				}
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
	
}
process
{
	try
	{
		$hostServerConfig = Get-PlHostServerConfiguration
		#region Hosts file
		if (-not (Get-PlHostEntry | where { $_.HostName -eq $hostServerConfig.Name -and $_.IPAddress -eq $hostServerConfig.IPAddress }))
		{
			Write-Verbose -Message "Host file entry for [$($hostServerConfig.Name)] doesn't exist. Adding..."
			Add-PlHostEntry -HostName $hostServerConfig.Name -IpAddress $hostServerConfig.IPAddress
		}
		else
		{
			Write-Verbose -Message "The host file entry for [$($hostServerConfig.Name)] already exists."
		}
		
		$plParams = @{
			'ComputerName' = $HostServerConfig.Name
			'Credential' = $HostServerConfig.Credential
			'HostName' = $env:COMPUTERNAME
			'IPAddress' = (Get-NetIPAddress -AddressFamily IPv4 | where { $_.PrefixOrigin -ne 'WellKnown' }).IPAddress
		}
		Add-PlHostEntry @plParams
		#endregion
		
		#region Add the host server to the trusted hosts
		Add-TrustedHostComputer -ComputerName $hostServerConfig.Name
		#endregion
		
		#region Enable remoting on the host server
		if (-not (Test-PsRemoting -computername $hostServerConfig.Name -Credential $hostServerConfig.Credential))
		{
			$wmiParams = @{
				'ComputerName' = $hostServerConfig.Name
				'Credential' = $hostServerConfig.Credential
				'Class' = 'Win32_Process'
				'Name' = 'Create'
				'Args' = 'c:\windows\system32\winrm.cmd quickconfig -quiet'
			}
			Write-Verbose -Message "PS remoting is not enabled. Enabling PS remoting on [$($hostServerConfig.Name)]"
			$process = Invoke-WmiMethod @wmiParams
			if ($process.ReturnValue -ne 0)
			{
				throw 'Enabling WinRM on host server failed'
			}
			else
			{
				Write-Verbose -Message 'Successfully enabled WinRM on host server'
			}
		}
		else
		{
			Write-Verbose -Message "PS remoting is already enabled on [$($hostServerConfig.Name)]"
		}
		#endregion
		
		#region Enable host server firewall ruls remote Hyper-V manager
		$sb = {
			Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'
			Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management'
			Enable-NetFirewallRule -DisplayGroup 'Remote Volume Management'
			Set-Service VDS -StartupType Automatic
		}
		Write-Verbose -Message "Adding necessary firewall rules to [$($hostServerConfig.Name)]"
		Invoke-Command -ComputerName $hostServerConfig.Name -Credential $hostServerConfig.Credential -ScriptBlock $sb
		#endregion
		
		#region Allow anonymous DCOM connections
		Write-Verbose -Message 'Adding the ANONYMOUS LOGON user to the local and host server Distributed COM Users group for Hyper-V manager'
		$sb = {
			$group = [ADSI]"WinNT://./Distributed COM Users"
			$members = @($group.Invoke("Members")) | foreach {
				$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
			}
			if ($members -notcontains 'ANONYMOUS LOGON')
			{
				$group = [ADSI]"WinNT://./Distributed COM Users,group"
				$group.add("WinNT://./NT AUTHORITY\ANONYMOUS LOGON")
			}
		}
		Invoke-Command -ComputerName $hostServerConfig.Name -Credential $hostServerConfig.Credential -ScriptBlock $sb
		& $sb
		#endregion
		
		Enable-NetFirewallRule -DisplayGroup 'Remote Volume Management'
	}
	catch
	{
		Write-Error $_.Exception.Message
	}
}