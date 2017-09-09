$configFilePath = "$($PSScriptRoot | Split-Path -Parent)\LabConfiguration.psd1"
$script:LabConfiguration = Import-PowerShellDataFile -Path $configFilePath

describe 'General VM configurations' {

	$vmConfig = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VMConfig
	$vms = $script:LabConfiguration.VirtualMachines
	$vhdConfig = $script:LabConfiguration.DefaultVirtualMachineConfiguration.VHDConfig
	$osConfig = $script:LabConfiguration.DefaultOperatingSystemConfiguration

	$icmParams = @{
		ComputerName = $script:LabConfiguration.HostServer.Name
	}
	$labVMs = Invoke-Command @icmParams -ScriptBlock { Get-Vm | where { $_.Name -match ($using:vms.BaseName -join '|')}}
	$labVhds = Invoke-Command @icmParams -ScriptBlock { Get-Vm -Name $using:LabVMs.Name | Get-VMHardDiskDrive }

	foreach ($vm in $labVMs) {
		it "the [$($vm.Name)] VM should have a $($vhdConfig.Size) [$($vhdConfig.Type)] drive attached" {
			# $vm.Sizing | should be $vhdConfig.Size
			# $vm.Type
		}

		it "the [$($vm.Name)] VM's VHD should have a $($vhdConfig.Sizing) sized VHDX" {

		}

		it "the [$($vm.Name)] VM's VHD should be located at $($vhdConfig.Path)" {

		}

		it "the [$($vm.Name)] VM's VHD should be partioned $($vhdConfig.PartionStyle)" {

		}

		it "the [$($vm.Name)] VM should have a memory of $($vmConfig.StartupMemory)" {

		}

		it "the [$($vm.Name)] VM should have a processor count of $($vmConfig.ProcessorCount)" {

		}

		it "the [$($vm.Name)] VM should be located at $($vmConfig.Path)" {

		}

		it "the [$($vm.Name)] VM should have a local user $($osConfig.User.Name) in the local admins group" {

		}

		it "the [$($vm.Name)] VM should have an IP in the $($osConfig.Network.IpNetwork) network" {

		}

		it "the [$($vm.Name)] VM should have the DNS server of $($osConfig.Network.DnsServer)" {

		}
	}
}

describe 'Web Server' {

	$webConfig = $script:LabConfiguration.DefaultServerConfiguration.Web
	$webVmConfig = $script:LabConfiguration.VirtualMachines | where {$_.Type -eq 'Web'}

	it "all web servers should have the base name of [$($webVmConfig.BaseName)]" {
		$result | should 
		
	}

	it "all web servers should have an operating system of [$($webVmConfig.OS)]" {
		$result | should 
		
	}

	it "all web servers should be running the [$($webVmConfig.Edition)] edition of Windows" {
		$result | should 
		
	}

	it "the IIS site name should be $($webConfig.WebsiteName)" {
		$result | should 
		
	}

	it "the IIS application pool on the site should be $($webConfig.ApplicationPoolName) " {
		$result | should 
		
	}
}

describe 'SQL Server' {

	$sqlConfig = $script:LabConfiguration.DefaultServerConfiguration.SQL
	$sqlVmConfig = $script:LabConfiguration.VirtualMachines | where {$_.Type -eq 'SQL'}

	it "all SQL servers should have the base name of [$($sqlVmConfig.BaseName)]" {
		$result | should 
		
	}

	it "all SQL servers should have an operating system of [$($sqlVmConfig.OS)]" {
		$result | should 
		
	}

	it "all SQL servers should be running the [$($sqlVmConfig.Edition)] edition of Windows" {
		$result | should 
		
	}

	it "the SQL administrator account should be $($sqlConfig.SystemAdministratorAccount.Name)" {
		$result | should 
		
	}

	it "the SQL agent service should be running under the $($sqlConfig.ServiceAccount.Name) account" {
		$result | should 
		
	}
}

describe 'Active Directory Forest' {

	$expectedAdConfig = $script:LabConfiguration.ActiveDirectoryConfiguration
	$adVmConfig = $script:LabConfiguration.VirtualMachines | where {$_.Type -eq 'Domain Controller'}
	$osConfig = $script:LabConfiguration.DefaultOperatingSystemConfiguration

	it "all domain controllers should have the base name of [$($adVmConfig.BaseName)]" {
		$result | should 
		
	}

	it "all domain controllers should have an operating system of [$($adVmConfig.OS)]" {
		$result | should 
		
	}

	it "all domain controllers should be running the [$($adVmConfig.Edition)] edition of Windows" {
		$result | should 
		
	}

	it "the domain mode should be $($expectedAdConfig.DomainMode)" {
		$result | should 
		
	}

	it "the forest mode should be $($expectedAdConfig.ForestMode)" {
		$result | should 
		
	}

	it "the name should be $($expectedAdConfig.DomainName)" {
		$result | should 
		
	}

	it "the IP address of the DC should be [$($osConfig.Network.DnsServer)]" {

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