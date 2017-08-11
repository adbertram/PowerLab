@{
	ProjectName = 'MyLab'

	## This will be the folder on the Hyper-V host that will be the base for all files needed
	ProjectRootFolder = 'C:\MyLab'
    
    ## This is the path on the Hyper-V hosts where you have the ISOs for each OS to install on the VMs is located
	IsoFolderPath = 'C:\MyLab\ISOs' 
    
    ## Each ISO file needs to be mapped to a particular operating system. Ensure every ISO is defined below with the operating system it is.
	ISOs = @( ## Define each
		@{
			FileName = 'en_windows_server_2012_r2_with_update_x64_dvd_4065220.iso' 
			OS = 'Windows Server 2016'
		}
	)

	Software = @{
		## This is the path where the SQL Server setup is located on the Hyper-V host
		SQLServerInstallerPath = 'C:\MyLab\SQLServer\setup.exe'
	}

    ## Define the name and IP address of the Hyper-V host here
	HostServer = @{
		Name = 'HYPERVSRV'
		IPAddress = '192.168.0.250'
	}

    ## This will be the default configuration for all Hyper-V components built by this Lab module
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

    ## Define as many VMs as you want here. Calling New-Lab will use this to find all of the VMs you'd like to provision
	## when building a new lab. When deploying more than one of a particular type of VM, the name here will be the base
	## name ie. SQLSRV, SQLSRV2, SQLSRV3, etc.
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
    
    ## Any Lab AD-specific configuration values go here.
	ActiveDirectoryConfiguration = @{
		DomainName = 'lab.local'
		DomainMode = 'Win2012R2'
		ForestMode = 'Win2012R2'
		SafeModeAdministratorPassword = 'p@$$w0rd12'
	}
}