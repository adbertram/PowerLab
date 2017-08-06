function Add-OperatingSystem
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory,ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[Microsoft.HyperV.PowerShell.VirtualMachine]$InputObject,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-IsValidOs $_})]
		[string]$OperatingSystem = (Get-PlDefaultVMConfig).OS.Name
		
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
		try
		{
			$vhdName = "$($InputObject.Name).$((Get-PlDefaultVHDConfig).Type)"
			Write-Verbose -Message "VHD name is [$($vhdName)]"
			if (Test-PlVhd -Name $vhdName)
			{
				throw "There is already a VHD called [$($vhdName)]"	
			}
			$vhd = New-PlVhd -Name $vhdName -OperatingSystem $OperatingSystem
			$InputObject | Add-VMHardDiskDrive -ComputerName $hostserver.Name -Path $vhd.ImagePath
			
			$bootOrder = ($InputObject | Get-VMFirmware).Bootorder
			if ($bootOrder[0].BootType -ne 'Drive')
			{
				$InputObject | Set-VMFirmware -FirstBootDevice $InputObject.HardDrives[0]
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function ConvertTo-VirtualDisk
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.vhdx?$')]
		[string]$VhdPath,
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$IsoFilePath,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$AnswerFilePath,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Dynamic', 'Fixed')]
		[string]$Sizing = (Get-PlDefaultVHDConfig).Sizing,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Edition = (Get-PlDefaultVMConfig).OS.Edition,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(512MB, 64TB)]
		[Uint64]$SizeBytes = (Invoke-Expression (Get-PlDefaultVHDConfig).Size),
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('VHD', 'VHDX')]
		[string]$VhdFormat = (Get-PlDefaultVHDConfig).Type,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$VHDPartitionStyle = (Get-PlDefaultVHDConfig).PartitionStyle,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
		
	)
	process
	{
		try
		{
			$convertFilePath = ((Get-PlConfigurationData).SelectSingleNode("//File[@Name='ISO to VHD Conversion Script' and @Location='HostServer']")).Path
			
			$sb = {
				. $using:convertFilePath
				$convertParams = @{
					SourcePath = $using:IsoFilePath
					SizeBytes = $using:SizeBytes
					Edition = $using:Edition
					VHDFormat = $using:VhdFormat
					VHDPath = $using:VhdPath
					VHDType = $using:Sizing
					VHDPartitionStyle = $using:VHDPartitionStyle
				}
				if (($using:PSBoundParameters).ContainsKey('AnswerFilePath')) {
					$convertParams.UnattendPath = $using:AnswerFilePath
				}
				if ($using:PassThru.IsPresent)
				{
					$convertParams.PassThru = $true	
				}
				Convert-WindowsImage @convertParams
			}
			Invoke-Command -ComputerName $HostServer.Name -Credential $HostServer.Credential -ScriptBlock $sb
		}
		catch
		{
			Write-Error -Message $_.Exception.Message
		}
	}
}

function New-PlVhd
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.vhdx?$')]
		[string]$Name,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(512MB, 1TB)]
		[int64]$Size = (Invoke-Expression (Get-PlDefaultVHDConfig).Size),
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Path = (Get-PlDefaultVHDConfig).Path,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Dynamic','Fixed')]
		[string]$Sizing = (Get-PlDefaultVHDConfig).Sizing,
	
		[Parameter(Mandatory,ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[string]$OperatingSystem,
	
		[Parameter(ParameterSetName = 'OSInstall')]
		[ValidateNotNullOrEmpty()]
		[string]$UnattendedXmlPath
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			
			$allowedOSes = (Get-PlConfigurationData).Configuration.ISOs.ISO.OS
			if ($OperatingSystem -notin $allowedOSes)
			{
				throw "The operating system [$($OperatingSystem)] is not configured. Use any of the following instead: $allowedOSes"
			}
			
			$sb = {
				if (-not (Test-Path -Path $using:Path -PathType Container))
				{
					$null = mkdir $using:Path	
				}
			}
			Invoke-Command -ComputerName $HostServer.Name -Credential $HostServer.Credential -ScriptBlock $sb
			
			$params = @{
				'SizeBytes' = $Size
			}
			if ($PSBoundParameters.ContainsKey('OperatingSystem'))
			{
				$cvtParams = $params + @{
					IsoFilePath = (Get-PlIsoFile -OperatingSystem $OperatingSystem).FullName
					VhdPath = "$Path\$Name"
					VhdFormat = ([system.io.path]::GetExtension($Name) -replace '^.')
					Sizing = $Sizing
					PassThru = $true
				}
				if ($PSBoundParameters.ContainsKey('UnattendedXmlPath')) {
					$cvtParams.AnswerFilePath = $UnattendedXmlPath
				}
				ConvertTo-VirtualDisk @cvtParams
			}
			else
			{
				$params.ComputerName = $HostServer.Name
				$params.Path = "$Path\$Name.$Type"
				if ($Sizing -eq 'Dynamic')
				{
					$params.Dynamic = $true
				}
				elseif ($Sizing -eq 'Fixed')
				{
					$params.Fixed = $true
				}
				New-VHD @params
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function Get-PlVhd
{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		[Parameter(ParameterSetName = 'Name')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.vhdx?$')]
		[string]$Name,
		
		[Parameter(ParameterSetName = 'Path')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^\w:.+\.vhdx?$')]
		[string]$Path
	
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
		function ConvertTo-UncPath
		{	
			[CmdletBinding()]
			param (
				[Parameter(Mandatory)]
				[string]$LocalFilePath,
				
				[Parameter(Mandatory)]
				[string]$ComputerName
			)
			process
			{
				$RemoteFilePathDrive = ($LocalFilePath | Split-Path -Qualifier).TrimEnd(':')
				"\\$ComputerName\$RemoteFilePathDrive`$$($LocalFilePath | Split-Path -NoQualifier)"
			}
		}
	}
	process
	{
		try
		{
			if ($PSCmdlet.ParameterSetName -eq 'None')
			{
				$vhdsPath = ConvertTo-UncPath -LocalFilePath (Get-PlDefaultVHDConfig).Path -ComputerName $HostServer.Name
				Get-ChildItem -Path $vhdsPath -File | foreach {
					Get-VHD -Path $_.FullName -ComputerName $HostServer.Name
				}
			}
			else
			{
				$vhdsPath = (Get-PlDefaultVHDConfig).Path
				if ($PSBoundParameters.ContainsKey('Name'))
				{
					$Path = "$vhdsPath\$Name"
				}
				try
				{
					Get-Vhd -Path $Path -ComputerName $HostServer.Name
				}
				catch [System.Management.Automation.ActionPreferenceStopException]
				{
					
				}
				
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}