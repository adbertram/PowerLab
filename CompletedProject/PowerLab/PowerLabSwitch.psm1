function Get-PlSwitch
{
	[CmdletBinding()]
	param
	()
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			$switch = (Get-PlConfigurationData).Environment.Switch
			$gsParams = @{
				'Name' = $switch.Name
				'SwitchType' = $switch.Type
			}
			Get-VMSwitch @gsParams
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}

function New-PlSwitch
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name = (Get-PlConfigurationData).Environment.Switch.Name,
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Internal','External')]
		[string]$SwitchType	= (Get-PlConfigurationData).Environment.Switch.Type
		
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			if (-not (Get-PlSwitch | where { $_.Name -eq $Name }))
			{
				$sParams = @{
					'Name' = $Name
					'SwitchType' = $SwitchType
				}
				New-VMSwitch @sParams
			}
			else
			{
				Write-Verbose -Message "The PowerLab switch [$($Name)] already exists."	
			}
		}
		catch
		{
			Write-Error $_.Exception.Message
		}
	}
}