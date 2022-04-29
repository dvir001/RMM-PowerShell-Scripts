Function WindowsDiskCleaner
{
	[ScriptBlock]$command = {
		# when changing StateFlags number please check run command for cleanmgr
		$SageSet = "StateFlags0099"
		$Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
		$Locations = @(
			"Active Setup Temp Folders"
			"BranchCache"
			"Content Index Cleaner"
			"D3D Shader Cache"
			"Delivery Optimization Files"
			"Device Driver Packages"
			"Diagnostic Data Viewer database files"
			"Downloaded Program Files"
			"Download Program Files"
			#  "DownloadsFolder"
			"GameNewsFiles"
			"GameStatisticsFiles"
			"GameUpdateFiles"
			"Internet Cache Files"
			"Language Pack"
			"Memory Dump Files"
			"Offline Pages Files"
			"Old ChkDsk Files"
			"Previous Installations"
			"Recycle Bin"
			"RetailDemo Offline Content"
			"Service Pack Cleanup"
			"Setup Log Files"
			"System error memory dump files"
			"System error minidump files"
			"Temporary Files"
			"Temporary Setup Files"
			#  "Temporary Sync Files"
			"Thumbnail Cache"
			"Update Cleanup"
			"Upgrade Discarded Files"
			"User file versions"
			"Windows Defender"
			"Windows Error Reporting Files"
			#  "Windows Error Reporting Archive Files"
			#  "Windows Error Reporting Queue Files"
			#  "Windows Error Reporting System Archive Files"
			#  "Windows Error Reporting System Queue Files"
			"Windows ESD installation files"
			"Windows Upgrade Log Files"
		)
		# value 2 means 'include' in cleanmgr run, 0 means 'do not run'
		ForEach ($Location in $Locations)
		{
			Set-ItemProperty -Path $($Base + $Location) -Name $SageSet -Type DWORD -Value 2 -ErrorAction SilentlyContinue | Out-Null
		}
		
		# do the cleanup . have to convert the SageSet number
		$cmdArgs = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length - 4)))"
		# Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $cmdArgs #-WindowStyle Hidden
		Start-Process -Wait -FilePath "$Env:ComSpec" -ArgumentList "/c title running Cleanmgr, please wait to complete&&echo Cleanmgr is running, please wait...&&cleanmgr /sagerun:99&&pause"
		
		# Remove the Stateflags
		ForEach ($Location in $Locations)
		{
			Remove-ItemProperty -Path $($Base + $Location) -Name $SageSet -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
	
	$commandDir = "$env:windir\Temp"
	$commandFile = "DiskClean.ps1"
	$triggerName = "DiskClean"
	
	function Set-CustomScheduledTask
	{
		if (!(Test-Path -Path $commandDir)) { New-Item -Path "$commandDir" -ItemType "directory" -Force } <# Lookup if the temp folder is there and create #>
		If (Test-Path "$commandDir\$commandFile") { Remove-Item -Path "$commandDir\$commandFile" -Force }
		If (!(test-path "$commandDir\$commandFile")) { New-Item -Path $commandDir -Name $commandFile -ItemType "file" -Value $command -Force | Out-Null }
		
		$oneTime = New-ScheduledTaskTrigger -Once -At (Get-Date)
		
		$Action = New-ScheduledTaskAction -Execute "powershell" -Argument "-executionpolicy bypass -noprofile -noninteractive -file `"$commandDir\$commandFile`"" # Specify what program to run and with its parameters
		$triggerSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries:$true -ExecutionTimeLimit "0" -MultipleInstances Parallel
		Register-ScheduledTask -TaskName $triggerName -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Action $Action -Trigger $oneTime -Settings $triggerSettings -Force # Specify the name of the task
	}
	
	Set-CustomScheduledTask
	Start-ScheduledTask -TaskName $triggerName
}

WindowsDiskCleaner
