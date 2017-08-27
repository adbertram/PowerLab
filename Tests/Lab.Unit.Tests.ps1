#region import modules
$ThisModule = "$($MyInvocation.MyCommand.Path -replace '\.Unit\.Tests\.ps1$', '').psm1"
$ThisModuleName = (($ThisModule | Split-Path -Leaf) -replace '\.psm1')
Get-Module -Name $ThisModuleName -All | Remove-Module -Force
Import-Module -Name $ThisModule -Force -ErrorAction Stop
#endregion

describe 'New-Lab' {
	$commandName = 'New-Lab'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'New-ActiveDirectoryForest' {
	$commandName = 'New-ActiveDirectoryForest'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'New-SqlServer' {
	$commandName = 'New-SqlServer'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'New-WebServer' {
	$commandName = 'New-WebServer'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'Install-IIS' {
	$commandName = 'Install-IIS'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'Install-SqlServer' {
	$commandName = 'Install-SqlServer'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'New-LabVm' {
	$commandName = 'New-LabVm'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'TestIsIsoNameValid' {
	$commandName = 'TestIsIsoNameValid'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'TestIsOsNameValid' {
	$commandName = 'TestIsOsNameValid'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'AddOperatingSystem' {
	$commandName = 'AddOperatingSystem'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'ConvertToVirtualDisk' {
	$commandName = 'ConvertToVirtualDisk'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'NewLabVhd' {
	$commandName = 'NewLabVhd'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'GetLabVhd' {
	$commandName = 'GetLabVhd'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'GetLabVm' {
	$commandName = 'GetLabVm'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'InvokeHyperVCommand' {
	$commandName = 'InvokeHyperVCommand'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'NewLabSwitch' {
	$commandName = 'NewLabSwitch'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'GetNextLabVmName' {
	$commandName = 'GetNextLabVmName'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'New-SqlServer' {
	$commandName = 'New-SqlServer'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'Test-Lab' {
	$commandName = 'Test-Lab'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'GetUnattendXmlFile' {
	$commandName = 'GetUnattendXmlFile'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}

describe 'PrepareUnattendXmlFile' {
	$commandName = 'PrepareUnattendXmlFile'

	#region Mocks

	#endregion

	context 'Param set label here' {

		$parameters = @{

		}

		$result = & $commandName @parameters

		it 'should return the expected number of objects' {
			@($result).Count | should be count
		}

		it 'should return the same object type in OutputType()' {
			$result | should beoftype $command.OutputType.Name
		}

	}

}