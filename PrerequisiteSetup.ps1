try {
	$HostServerConfig = @{
		Name = Read-Host -Prompt 'Name of your HYPERV host'
		IPAddress = Read-Host -Prompt 'IP address of your HYPERV host'
		Credential = Get-Credential -Message 'Local username/password to connect to your Hyper-V host'
	}

	#region Functions
		function Add-PlHostEntry
		{
			[CmdletBinding()]
			param
			(
				
				[Parameter(Mandatory)]
				[ValidateNotNullOrEmpty()]
				[ValidatePattern('^[^\.]+$')]
				[string]$HostName,
				
				[Parameter(Mandatory)]
				[ValidateNotNullOrEmpty()]
				[ipaddress]$IpAddress,
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$Comment,
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$ComputerName = $env:COMPUTERNAME,
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[pscredential]$Credential,
			
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$HostFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
				
						
			)
			begin {
				$ErrorActionPreference = 'Stop'
			}
			process {
				try
				{
					$IpAddress = $IpAddress.IPAddressToString
					
					$getParams = @{ }
					if ($ComputerName -ne $env:COMPUTERNAME)
					{
						$getParams.ComputerName = $ComputerName
						$getParams.Credential = $Credential
					}
					
					$existingHostEntries = Get-PlHostEntry @getParams
					
					if ($result = $existingHostEntries | where HostName -EQ $HostName)
					{
						throw "The hostname [$($HostName)] already exists in the host file with IP [$($result.IpAddress)]"
					}
					elseif ($result = $existingHostEntries | where IPAddress -EQ $IpAddress)
					{
						Write-Warning "The IP address [$($result.IPAddress)] already exists in the host file for the hostname [$($HostName)]. You should probabloy remove the old one hostname reference."
					}
					$vals = @(
						$IpAddress
						$HostName
					)
					if ($PSBoundParameters.ContainsKey('Comment')) {
						$vals += "# $Comment"
					}
					
					$sb = {
						param($HostFilePath,$vals)
						
						## If the hosts file doesn't end with a blank line, make it so
						if ((Get-Content -Path $HostFilePath -Raw) -notmatch '\n$')
						{
							Add-Content -Path $HostFilePath -Value ''
						}
						Add-Content -Path $HostFilePath -Value ($vals -join "`t")
					}
					
					if ($ComputerName -eq (hostname))
					{
						& $sb $HostFilePath $vals
					}
					else
					{
						$icmParams = @{
							'ComputerName' = $ComputerName
							'ScriptBlock' = $sb
							'ArgumentList' = $HostFilePath,$vals
						}
						if ($PSBoundParameters.ContainsKey('Credential'))
						{
							$icmParams.Credential = $Credential
						}
						[pscustomobject](Invoke-Command @icmParams)
					}
					
					
				}
				catch
				{
					Write-Error $_.Exception.Message
				}
			}
		}

		function Get-PlHostEntry
		{
			[CmdletBinding()]
			[OutputType([System.Management.Automation.PSCustomObject])]
			param
			(
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$ComputerName = $env:COMPUTERNAME,
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[pscredential]$Credential,
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$HostFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
				
			)
			begin {
				$ErrorActionPreference = 'Stop'
			}
			process {
				try
				{
					$sb = {
						param($HostFilePath)
						$regex = '^(?<ipAddress>[0-9.]+)[^\w]*(?<hostname>[^#\W]*)($|[\W]{0,}#\s+(?<comment>.*))'
						$matches = $null
						Get-Content -Path $HostFilePath | foreach {
							$null = $_ -match $regex
							if ($matches)
							{
								@{
									'IPAddress' = $matches.ipAddress
									'HostName' = $matches.hostname
								}
							}
							$matches = $null
						}
					}
					
					if ($ComputerName -eq (hostname))
					{
						& $sb $HostFilePath
					}
					else
					{
						$icmParams = @{
							'ComputerName' = $ComputerName
							'ScriptBlock' = $sb
							'ArgumentList' = $HostFilePath
						}
						if ($PSBoundParameters.ContainsKey('Credential'))
						{
							$icmParams.Credential = $Credential
						}
						[pscustomobject](Invoke-Command @icmParams)
					}
				}
				catch
				{
					Write-Error $_.Exception.Message
				}
			}
		}

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
	#endregion

	if (-not (Get-PlHostEntry | where HostName -eq $hostServerConfig.Name)) {
		Write-Host -Object 'Adding local hosts entry for Hyper-V host...'
		Add-PlHostEntry -HostName $hostServerConfig.Name -IpAddress $hostServerConfig.IPAddress
	}

	Write-Host -Object 'Enabling PS remoting on local computer...'
	$null = Enable-PSRemoting -Force -SkipNetworkProfileCheck

	Write-Host -Object 'Adding server to trusted computers...'
	Add-TrustedHostComputer -ComputerName $hostServerConfig.Name
	
	$plParams = @{
		'ComputerName' = $HostServerConfig.Name
		'Credential' = $HostServerConfig.Credential
		'HostName' = $env:COMPUTERNAME
		'IPAddress' = (Get-NetIPAddress -AddressFamily IPv4 | where { $_.PrefixOrigin -ne 'WellKnown' }).IPAddress
	}
	if (-not (Get-PlHostEntry -ComputerName $plParams.ComputerName -Credential $HostServerConfig.Credential | where HostName -eq $plParams.HostName)) {
		Write-Host -Object 'Adding hosts entry for local computer on Hyper-V host...'
		Add-PlHostEntry @plParams
	}

	if (-not (Test-PsRemoting -computername $hostServerConfig.Name -Credential $hostServerConfig.Credential))
	{
		$wmiParams = @{
			'ComputerName' = $hostServerConfig.Name
			'Credential' = $hostServerConfig.Credential
			'Class' = 'Win32_Process'
			'Name' = 'Create'
			'Args' = 'c:\windows\system32\winrm.cmd quickconfig -quiet'
		}
		Write-Host -Object "PS remoting is not enabled. Enabling PS remoting on [$($hostServerConfig.Name)]"
		$process = Invoke-WmiMethod @wmiParams
		if ($process.ReturnValue -ne 0)
		{
			throw 'Enabling WinRM on host server failed'
		}
		else
		{
			Write-Host -Object 'Successfully enabled WinRM on host server'
		}
	}
	else
	{
		Write-Host -Object "PS remoting is already enabled on [$($hostServerConfig.Name)]"
	}
	
	Write-Host -Object 'Setting firewall rules on Hyper-V host...'
	$sb = {
		Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'
		Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management'
		Enable-NetFirewallRule -DisplayGroup 'Remote Volume Management'
		Set-Service VDS -StartupType Automatic
	}
	Invoke-Command -ComputerName $hostServerConfig.Name -Credential $hostServerConfig.Credential -ScriptBlock $sb
	
	$sb = {
		$group = [ADSI]"WinNT://./Distributed COM Users"
		$members = @($group.Invoke("Members")) | foreach {
			$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
		}
		if ($members -notcontains 'ANONYMOUS LOGON')
		{
			$group = [ADSI]"WinNT://./Distributed COM Users,group"
			$group.add("WinNT://./NT AUTHORITY/ANONYMOUS LOGON")
		}
	}
	Write-Host -Object 'Adding the ANONYMOUS LOGON user to the local machine and host server Distributed COM Users group for Hyper-V manager'
	Invoke-Command -ComputerName $hostServerConfig.Name -Credential $hostServerConfig.Credential -ScriptBlock $sb
	& $sb
	
	Write-Host -Object 'Enabling applicable firewall rules on local machine...'
	Enable-NetFirewallRule -DisplayGroup 'Remote Volume Management'

	Write-Host -Object 'Adding saved credential on local computer for Hyper-V host...'
	if ((cmdkey /list:($HostServerConfig.Name)) -match '\* NONE \*') {
		$null = cmdkey /add:($HostServerConfig.Name) /user:($HostServerConfig.Credential.UserName) /pass:($HostServerConfig.Credential.GetNetworkCredential().Password)
	}

	Write-Host -Object 'Lab setup is now complete.' -ForegroundColor Green
} catch {
	Write-Warning $_.Exception.Message
}