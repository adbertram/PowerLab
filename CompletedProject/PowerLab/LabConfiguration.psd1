@{
	ProjectName = 'Lab'
	IsoFolderPath = 'C:\Lab\ISOs'
	UnattendXmlsFolderPath = 'C:\Lab\AutoUnattend'
	VHDConversionScriptPath = 'C:\Lab\Convert-WindowsImage.ps1'
	ISOs = @(
		@{
			FileName = 'en_windows_server_2012_r2_with_update_x64_dvd_4065220.iso' 
			OS = 'Windows Server 2016'
		}
	)
	HostServer = @{
		Name = 'HYPERVSRV'
		IPAddress = '192.168.0.250'
	} 
	DefaultVirtualMachineConfiguration = @{
		VirtualSwitch = @{
			Name = 'Lab'
			Type = 'Internal'
		}
		VHDConfig = @{
			Size = '40GB' 
			Type = 'VHDX' 
			Sizing = 'Dynamic' 
			Path = 'C:\Lab\VHDs' 
			PartitionStyle = 'GPT'
		} 
		VMConfig = @{
			StartupMemory = '4GB' 
			ProcessorCount = 1 
			Path = 'C:\Lab\VMs' 
			Generation = 2
			OSEdition = 'ServerStandardCore'
		}
	}
	VirtualMachines = @(
		@{
			Name = 'SQLSRV'
			Type = 'SQL'
			OS = 'Windows Server 2016'
			Edition = 'ServerStandardCore'
		}
		@{
			Name = 'WEBSRV'
			Type = 'Web'
			OS = 'Windows Server 2016'
			Edition = 'ServerStandardCore'
		}
		@{
			Name = 'LABDC'
			Type = 'Domain Controller'
			OS = 'Windows Server 2016' 
			Edition = 'ServerStandardCore'
		}
	)
	ActiveDirectoryConfiguration = @{
		DomainName = 'lab.local'
	}
}