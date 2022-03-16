<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2021 v5.8.191
	 Created on:   	19/01/2022 13:40
	 Created by:   	dvir
	 Organization: 	ITMS
	 Filename:     	OneDrive - Startup At Unlock
	===========================================================================
	.DESCRIPTION
		OneDrive - Startup At Unlock.
#>

#Requires -Version 5.0

function Run-ScriptBlock
{
	[ScriptBlock]$command = {
		[ScriptBlock]$scriptBlock = {
			$fileFolder = "${env:ProgramFiles}\Microsoft OneDrive"
			$file = "OneDrive.exe"
			$argument = "/background"
			
			If (test-path "$fileFolder\$file") { Start-Process -FilePath "$fileFolder\$file" -ArgumentList $argument }
		}
		
		Invoke-AsCurrentUser -ScriptBlock $scriptBlock -CacheToDisk -NonElevatedSession -ErrorAction SilentlyContinue <# Set Default app #>
	}
	
	$commandDir = "$env:ProgramFiles\ITMS"
	$commandFile = "OneDrive-Config-Startup.ps1"
	$triggerName = "OneDrive Startup At Unlock"
	
	[ScriptBlock]$scriptTaskExists = {
		
	}
	
	[ScriptBlock]$scriptTaskExistsElse = {
		
	}
	
	function Set-CustomScheduledTask
	{
		if (!(Test-Path -Path $commandDir)) { New-Item -Path "$commandDir" -ItemType "directory" -Force } <# Lookup if the temp folder is there and create #>
		If (Test-Path "$commandDir\$commandFile") { Remove-Item -Path "$commandDir\$commandFile" -Force }
		If (!(test-path "$commandDir\$commandFile")) { New-Item -Path $commandDir -Name $commandFile -ItemType "file" -Value $command -Force | Out-Null }
		
		$taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -like $triggerName }
		if ($taskExists) { Invoke-Command -Command $scriptTaskExists }
		else { Invoke-Command -Command $scriptTaskExistsElse }
		
		$stateChangeTrigger = Get-CimClass ` -Namespace ROOT\Microsoft\Windows\TaskScheduler ` -ClassName MSFT_TaskSessionStateChangeTrigger
		$onUnlockTrigger = New-CimInstance ` -CimClass $stateChangeTrigger ` -Property @{ StateChange = 8 <# TASK_SESSION_STATE_CHANGE_TYPE.TASK_SESSION_UNLOCK (taskschd.h) #> } ` -ClientOnly
		$onLogin = New-ScheduledTaskTrigger -AtLogOn
		
		$Action = New-ScheduledTaskAction -Execute "powershell" -Argument "-executionpolicy bypass -noprofile -noninteractive -file `"$commandDir\$commandFile`"" # Specify what program to run and with its parameters
		$triggerSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries:$true -ExecutionTimeLimit "0" -MultipleInstances Parallel
		Register-ScheduledTask -TaskName $triggerName -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Trigger $onUnlockTrigger -Action $Action -Settings $triggerSettings -Force # Specify the name of the task
	}
	
	Set-CustomScheduledTask
	#Start-ScheduledTask -TaskName $triggerName
}

function Install-CustomModule
{
	param (
		[Parameter(Mandatory = $true)]
		[array]$modules
	)
	foreach ($module in $modules)
	{
		try
		{
			#Write-Output "Importing module '$module'"
			Import-Module $module -ErrorAction Stop
		}
		catch
		{
			Write-Output "Could not find '$module' module, installing..."
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose:$false *>$null
			Install-Module -Name $module -Scope AllUsers -AllowClobber -Force
			Import-Module $module -ErrorAction Stop
			#Write-Output "Importing module '$module'"
		}
	}
}

Install-CustomModule -modules "RunAsUser"
Run-ScriptBlock
