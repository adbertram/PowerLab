$configFilePath = "$($PSScriptRoot | Split-Path -Parent)\LabConfiguration.psd1"
$script:LabConfiguration = Import-PowerShellDataFile -Path $configFilePath

describe 'Web Server' {

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

	}
}

describe 'SQL Server' {

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

	}
}

describe 'Active Directory Forest' {

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

	}
}

describe 'Hyper-V Lab Infrastructure' {

	$uncProjectRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.ProjectRootFolder -ComputerName $script:LabConfiguration.HostServer.Name
	$isoRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.IsoFolderPath -ComputerName $script:LabConfiguration.HostServer.Name
	$vhdRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig.Path -ComputerName $script:LabConfiguration.HostServer.Name
	$vmRoot = ConvertToUncPath -LocalFilePath $script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig.Path -ComputerName $script:LabConfiguration.HostServer.Name

	it 'the Hyper-V host is up' {
		Test-Connection -ComputerName $script:LabConfiguration.HostServer.Name -Quiet -Count 1 | should be $true
	}

	it 'The path to the ProjectRooFolder exists' {
		Test-Path -Path $uncProjectRoot -PathType Container | should be $true
	}

	it 'the path to the IsoFolderPath exists' {
		Test-Path -Path $isoRoot -PathType Container | should be $true
	}

	it 'the default VHD root path exists' {
		Test-Path -Path $vhdRoot -PathType Container | should be $true	
	}

	it 'the default VM root path exists' {
		Test-Path -Path $vmRoot -PathType Container | should be $tru
	}

	it 'all ISOs defined in configuration exist' {
		@($script:LabConfiguration.ISOs).where({ -not (Test-Path -Path "$isoRoot\$($_.FileName)" -PathType Leaf)}) | should benullOrEmpty
	}

	it 'all operating systems defined in the configuration have an unattend.xml' {
		$validNames = $script:LabConfiguration.ISOs.where({ $_.Type -eq 'OS'}).Name
		$xmlFiles = Get-ChildItem "$PSScriptRoot\AutoUnattend" -Filter '*.xml' -File
		$validxmlFiles = $xmlFiles | Where-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -in $validNames }
		@($validNames).Count | shoud be  @($validXmlFiles).Count
	}

	it 'all VMs in configuration have a corresponding ISO available' {
		$validOses = $script:LabConfiguration.ISOs.where({ $_.Type -eq 'OS'}).Name
		$vmOsesDefined = $script:LabConfiguration.VirtualMachines.OS
		$vmOsesDefined.where({ $_ -notin $validOses}) | should benullOrEmpty
	}
}