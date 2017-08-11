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

		function Get-InstalledSoftware
		{
			<#
			.SYNOPSIS
				Retrieves a list of all software installed on a Windows computer.
			.EXAMPLE
				PS> Get-InstalledSoftware
				
				This example retrieves all software installed on the local computer.
			.PARAMETER ComputerName
				If querying a remote computer, use the computer name here.
			
			.PARAMETER Name
				The software title you'd like to limit the query to.
			
			.PARAMETER Guid
				The software GUID you'e like to limit the query to
			#>
			[CmdletBinding()]
			param (
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$ComputerName = $env:COMPUTERNAME,
				
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$Name,
				
				[Parameter()]
				[string]$Guid
			)
			process
			{
				try
				{
					$scriptBlock = {
						$args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }
						
						$UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
						New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
						$UninstallKeys += Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
						if (-not $UninstallKeys)
						{
							Write-Warning -Message 'No software registry keys found'
						}
						else
						{
							foreach ($UninstallKey in $UninstallKeys)
							{
								$friendlyNames = @{
									'DisplayName' = 'Name'
									'DisplayVersion' = 'Version'
								}
								Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
								if ($Name)
								{
									$WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
								}
								elseif ($GUID)
								{
									$WhereBlock = { $_.PsChildName -eq $Guid }
								}
								else
								{
									$WhereBlock = { $_.GetValue('DisplayName') }
								}
								$SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
								if (-not $SwKeys)
								{
									Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
								}
								else
								{
									foreach ($SwKey in $SwKeys)
									{
										$output = @{ }
										foreach ($ValName in $SwKey.GetValueNames())
										{
											if ($ValName -ne 'Version')
											{
												$output.InstallLocation = ''
												if ($ValName -eq 'InstallLocation' -and ($SwKey.GetValue($ValName)) -and (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\')))
												{
													$output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
												}
												[string]$ValData = $SwKey.GetValue($ValName)
												if ($friendlyNames[$ValName])
												{
													$output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
												}
												else
												{
													$output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
												}
											}
										}
										$output.GUID = ''
										if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')
										{
											$output.GUID = $SwKey.PSChildName
										}
										[pscustomobject]$output
									}
								}
							}
						}
					}
					
					if ($ComputerName -eq $env:COMPUTERNAME)
					{
						& $scriptBlock $PSBoundParameters
					}
					else
					{
						Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
					}
				}
				catch
				{
					Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
				}
			}
		}

		function Install-RSAT
		{
			[CmdletBinding()]
			param
			(
				[Parameter()]
				[ValidateNotNullOrEmpty()]
				[string]$Url = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS2016-x64.msu'
				
			)
			begin
			{
				$ErrorActionPreference = 'Stop'
			}
			process
			{
				try
				{
					#region RSAT download
					$downloadedFilePath = "$env:TEMP\$($Url | Split-Path -Leaf)"
					if (-not (Test-Path -Path $downloadedFilePath -PathType Leaf))
					{
						Invoke-WebRequest -Uri $Url -OutFile $downloadedFilePath
					}
					else
					{
						Write-Verbose -Message "The file [$($downloadedFilePath)] already exists. Using that one to install RSAT."
					}
					#endregion
					
					#region RSAT install
					$null = Start-Process -FilePath 'WUSA.exe' -Args "$downloadedFilePath /QUIET /NORESTART" -Wait -NoNewWindow
					#endregion
				}
				catch
				{
					Write-Error $_.Exception.Message
				}
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

	if (-not (Get-InstalledSoftware | where { $_.Name -like '*Remote Server Administration Tools*' })) {
		$rsatInstall = Read-Host -Prompt 'RSAT for Windows 10 is not installed. Install now? (Y,N)'
		if ($rsatInstall -eq 'Y') {
			Write-Host 'Downloading and installing RSAT for Windows 10. This may take a minute..'
			Install-Rsat
			Write-Host 'Done.'
		} else {
			Write-Host -Object 'RSAT must be installed before using this Lab module. It can be downloaded from https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS2016-x64.msu' -ForegroundColor Red
		}
	}

	if (-not ($hyperVToolFeature = dism /online /get-features | select-string -Pattern 'Microsoft-Hyper-V-Tools-All' -Context 1)) {
		throw 'The required feature for Hyper-V is not installed. Did you install RSAT?'
	} elseif ($hyperVToolFeature.Context.PostContext -notmatch 'Enabled') {
		Write-Host 'Enabling the Hyper-V management features...'
		dism /online /Enable-Feature /FeatureName:Microsoft-Hyper-V-Tools-All /All
	}

	Write-Host -Object 'Ensure all values in the Lab configuration file are valid.'
	ise "$PSscriptRoot\LabConfiguration.psd1"

	Write-Host -Object 'Lab setup is now complete.' -ForegroundColor Green
} catch {
	Write-Warning $_.Exception.Message
}