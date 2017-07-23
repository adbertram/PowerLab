@{
	VirtualMachines = @(
		@{
			Name = 'TESTENV1-DC'
			ServerRole = 'DomainController'
		}
		@{
			Name = 'TESTENV1-SQL'
			ServerRole = 'SQLServer'
		}
		@{
			Name = 'TESTENV1-IIS'
			ServerRole = 'WebServer'
		}
	)
	Servers = @(
		@{
			Name = 'TESTENV1-DC'
		}
		@{
			Name = 'TESTENV1-SQL'
		}
		@{
			Name = 'TESTENV1-IIS'
		}
	)
	ServerRoles = @(
		DomainController = @{
			RequiredMemory = 2048
			RequiredStorage = 40GB
			RequiredOperatingSystem = 'Windows Server 2012 R2'
			Install = @{
				WindowsFeatures = @(
					@{ Name = '' }
				)
			}
			Configuration = @{
				Users = @(

				)
				Groups = @(

				)
				OrganizationalUnits = @(

				)
			}
		}

		SQLServer = @{
			RequiredMemory = 2048
			RequiredStorage = 40GB
			RequiredOperatingSystem = 'Windows Server 2012 R2'
			Install = @{
				SourcePath = ''
			}
			Configuration = @{
				Databases = @(

				)
			}
		}

		WebServer = @{
			RequiredMemory = 2048
			RequiredStorage = 40GB
			RequiredOperatingSystem = 'Windows Server 2012 R2'
			Install = @{
				WindowsFeatures = @(
					@{ Name = ''}
				)
			}
			Configuration = @{
				Users = @(

				)
				Groups = @(

				)
				OrganizationalUnits = @(

				)
			}
		}
	)
}