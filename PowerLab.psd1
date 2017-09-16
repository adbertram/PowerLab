@{
	RootModule        = 'PowerLab.psm1'
	ModuleVersion     = '1.0.0'
	GUID              = '3aad272a-fb09-41a2-8208-f3eaa1c3e7a5'
	Author            = 'Adam Bertram'
	CompanyName       = 'Adam the Automator, LLC'
	PowerShellVersion = '5.0'
	RequiredModules   = 'Hyper-V'
	FunctionsToExport = 'New-Lab', 'Remove-Lab', 'New-ActiveDirectoryForest', 'New-SqlServer', 'New-WebServer', 'Get-LabVm', 'Get-LabVhd'
	FileList          = 'PowerLabConfiguration.psd1', 'Convert-WindowsImage.ps1', 'SQLServer.ini', 'Install-PowerLab.ps1', 'AutoUnattend'
	PrivateData       = @{
		PSData = @{
			Tags       = 'PowerLab'
			ProjectUri = 'https://github.com/adbertram/PowerLab'
		}
	}
}

