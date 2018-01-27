@{
	ProjectName                         = 'PowerLab'

	## This will be the folder on the Hyper-V host that will be the base for all files needed
	ProjectRootFolder                   = 'C:\PowerLab'
    
	## This is the path on the Hyper-V hosts where you have the ISOs for each OS to install on the VMs is located
	IsoFolderPath                       = 'C:\PowerLab\ISOs' 

	## The unattended XML file template that's used to create an answer file for all new OS installs
	UnattendXmlPath                     = '.\AutoUnattend'
    
	## Each ISO file needs to be mapped to a particular label. Ensure every ISO is defined with a label.
	ISOs                                = @( ## Define each
		@{
			FileName   = 'en_windows_server_2016_x64_dvd_9718492.iso'
			Type       = 'OS'
			Name       = 'Windows Server 2016'
			ProductKey = ''
		}
		@{
			FileName   = 'en_sql_server_2016_standard_x64_dvd_8701871.iso' 
			Type       = 'Software'
			Name       = 'SQL Server 2016'
			ProductKey = ''
		}
		@{
			FileName   = 'en_windows_server_2012_r2_with_update_x64_dvd_4065220.iso' 
			Type       = 'OS'
			Name       = 'Windows Server 2012 R2'
			ProductKey = ''
		}
	)

	## Define the name and IP address of the Hyper-V host here
	HostServer                          = @{
		Name      = 'HYPERVSRV'
		IPAddress = '192.168.0.250'
	}

	## This will be the default configuration for all Hyper-V components built by this Lab module
	DefaultVirtualMachineConfiguration  = @{
		VirtualSwitch = @{
			Name = 'PowerLab'
			Type = 'External' ## This is in order for our client to communicate with the VMs. If this is external, we'll ignore this one and use the existing one (if exists)
		}
		VHDConfig     = @{
			Size           = '40GB' 
			Type           = 'VHDX' 
			Sizing         = 'Dynamic' 
			Path           = 'C:\PowerLab\VHDs' 
			PartitionStyle = 'GPT'
		} 
		VMConfig      = @{
			StartupMemory  = '2GB' 
			ProcessorCount = 1 
			Path           = 'C:\PowerLab\VMs' 
			Generation     = 2
			OSEdition      = 'ServerStandardCore'
		}
	}

	DefaultOperatingSystemConfiguration = @{
		Users   = @(
			@{
				Name     = 'PowerLabUser'
				Password = 'P@$$w0rd12'
			}
			@{
				Name     = 'Administrator'
				Password = 'P@$$w0rd12'
			}
		)

		Network = @{
			IpNetwork = '192.168.0.0' ## Ensure this network does not conflict with any existing
			DnsServer = '192.168.0.100' ## This will also be the IP of the domain controller (if deployed)
		}
	}

	DefaultServerConfiguration          = @{
		Web = @{
			ApplicationPoolName = 'AutomateBoringStuff'
			WebSiteName         = 'AutomateBoringStuff'
		}
		SQL = @{
			SystemAdministratorAccount = @{
				Name = 'PowerLabUser'
			}
			ServiceAccount             = @{
				Name     = 'PowerLabUser'
				Password = 'P@$$w0rd12'
			}
		}
	}

	## Define as many VM types as you want here. Calling New-PowerLab will use this to find all of the VMs you'd like to provision
	## when building a new lab. When deploying more than one of a particular type of VM, the name here will be the base
	## name ie. SQLSRV, SQLSRV2, SQLSRV3, etc.
	VirtualMachines                     = @(
		@{
			BaseName = 'SQLSRV'
			Type     = 'SQL'
			OS       = 'Windows Server 2016'
			Edition  = 'ServerStandardCore'
		}
		@{
			BaseName = 'WEBSRV'
			Type     = 'Web'
			OS       = 'Windows Server 2016'
			Edition  = 'ServerStandardCore'
		}
		@{
			BaseName = 'LABDC'
			Type     = 'Domain Controller'
			OS       = 'Windows Server 2016' 
			Edition  = 'ServerStandardCore'
		}
	)
    
	## Any Lab AD-specific configuration values go here.
	ActiveDirectoryConfiguration        = @{
		DomainName                    = 'powerlab.local'
		DomainMode                    = 'Win2012R2'
		ForestMode                    = 'Win2012R2'
		SafeModeAdministratorPassword = 'P@$$w0rd12'
	}
}