<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2021 v5.8.191
	 Created on:   	10/03/2022 13:01
	 Created by:   	dvir
	 Organization: 	ITMS
	 Filename:     	Teams - Set Preference.ps1
	===========================================================================
	.DESCRIPTION
		This script will change the the users Teams configuration file, openAsHidden, registerAsIMProvider.
	.INPUTS
   		The following switches are available:
    	-openAsHidden          (minimizes Teams to systray on startup)
    	-disableAutoStart      (Stops Teams frostarting with the OS)
    	-registerAsIMProvider  (Makes Teams the default Instant Messaging Provider for the user)
    	-exitOnClose           (Makes the Teams client exit when the main windows is closed)
		.OUTPUTS
    	A log file called Set-UserTeamsPreference_Script-log.txt is written to the users own TEMP folder at each execution of the script (overwriting the previous log).
	.NOTES
    	Original COPYRIGHT:
    	@michael_mardahl / https://www.iphase.dk
	.EXAMPLE
    	Run the script as is in the users context, to set defaults
#>

#Requires -Version 5.0

function Run-ScriptBlock
{
	[ScriptBlock]$command = {
		[ScriptBlock]$scriptBlock = {
			
			function Stop-CustomService
			{
				param (
					[Parameter(Mandatory = $true)]
					[array]$Services
				)
				foreach ($service in $services)
				{
					if (Get-Process -Name $service -IncludeUserName | Where-Object -Property Username -like "*$ENV:USERNAME*")
					{ Stop-Process -Name $service -Force }
				}
			}
			
			function Set-UserTeamsPreference
			{
				PARAM (
					[switch]$openAsHidden,
					[switch]$disableAutoStart,
					[switch]$registerAsIMProvider,
					[switch]$exitOnClose
				)
				
				$VerbosePreference = "Continue" <# Enabling verbose output for our log #>
				$configFile = "$ENV:APPDATA\Microsoft\Teams\desktop-config.json" <# The users Teams configuration file #>
				
				# Logging any errors to the users temp folder
				Start-Transcript -Path "$env:TEMP\Set-UserTeamsPreference_Script-log.txt"
				Write-Output "Modifying the users Teams client..."
				
				# Load the file data into a variable
				Write-Verbose "Fetching the contents of $configFile"
				try { $fileBuffer = Get-Content $configFile -ErrorAction Stop }
				catch { Write-Error "Could not fetch the users Teams config file! Make sure Teams is installed!"; Stop-Transcript; exit 1 }
				
				#Closing Teams just in case (sorry users!)
				
				# Hidden option
				if ($openAsHidden)
				{
					if ($fileBuffer -like '*"openAsHidden":false*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Enabling the "openAsHidden" option...'; $fileBuffer = $fileBuffer -replace '"openAsHidden":false', '"openAsHidden":true'
					}
				}
				else
				{
					if ($fileBuffer -like '*"openAsHidden":true*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Disabling the "openAsHidden" option...'; $fileBuffer = $fileBuffer -replace '"openAsHidden":true', '"openAsHidden":false'
					}
				}
				
				# Autostart option
				if ($disableAutoStart)
				{
					if ($fileBuffer -like '*"openAtLogin":true*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Disabling the "openAtLogin" option...'; $fileBuffer = $fileBuffer -replace '"openAtLogin":true', '"openAtLogin":false'
					}
				}
				else
				{
					if ($fileBuffer -like '*"openAtLogin":false*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Enabling the "openAtLogin" option...'; $fileBuffer = $fileBuffer -replace '"openAtLogin":false', '"openAtLogin":true'
					}
				}
				
				# IM Provider option
				if ($registerAsIMProvider)
				{
					if ($fileBuffer -like '*"registerAsIMProvider":false*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Enabling the "registerAsIMProvider" option...'
						$fileBuffer = $fileBuffer -replace '"registerAsIMProvider":false', '"registerAsIMProvider":true'
						New-ItemProperty -Path "HKCU:\SOFTWARE\IM Providers" -Name DefaultIMApp -Value Teams -PropertyType STRING -Force -ErrorAction SilentlyContinue
					}
				}
				else
				{
					if ($fileBuffer -like '*"registerAsIMProvider":true*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Disabling the "registerAsIMProvider" option...'
						$fileBuffer = $fileBuffer -replace '"registerAsIMProvider":true', '"registerAsIMProvider":false'
						$imProviders = "HKCU:\SOFTWARE\IM Providers"
						$teamsIMProvider = "HKCU:\SOFTWARE\IM Providers\Teams"
						if (Test-Path -Path $teamsIMProvider)
						{
							$previousDefaultIMApp = (Get-ItemProperty -Path $teamsIMProvider -Name PreviousDefaultIMApp -ErrorAction SilentlyContinue).PreviousDefaultIMApp
							if ($previousDefaultIMApp) { New-ItemProperty -Path $imProviders -Name DefaultIMApp -Value $previousDefaultIMApp -PropertyType STRING -Force }
							else { Remove-ItemProperty -Path $imProviders -Name DefaultIMApp -ErrorAction SilentlyContinue }
						}
					}
				}
				
				# Program close behaviour option
				if ($exitOnClose)
				{
					if ($fileBuffer -like '*"runningOnClose":true*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Disabling the "runningOnClose" option...'; $fileBuffer = $fileBuffer -replace '"runningOnClose":true', '"runningOnClose":false'
					}
				}
				else
				{
					if ($fileBuffer -like '*"runningOnClose":false*')
					{
						Stop-CustomService -Services Teams
						Write-Verbose 'Enabling the "runningOnClose" option...'; $fileBuffer = $fileBuffer -replace '"runningOnClose":false', '"runningOnClose":true'
					}
				}
				
				# Output our modified data back into the configuration file, force overwriting the contents
				Write-Verbose "Overwriting the contents of $configFile"
				$fileBuffer | Set-Content $configFile -Force
				
				# Start teams
				if (!(Get-Process -Name "Teams" -IncludeUserNam | Where-Object -Property Username -like "*$ENV:USERNAME*"))
				{
					if (Test-Path "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe")
					{ Start-Process -FilePath "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe" -ArgumentList '--processStart "Teams.exe" --process-start-args "--system-initiated"' }
					else
					{
						if (Test-Path "$($env:USERProfile)\AppData\Local\Microsoft\Teams\Update.exe")
						{ Start-Process -File "$($env:USERProfile)\AppData\Local\Microsoft\Teams\Update.exe" -ArgumentList '--processStart "Teams.exe" --process-start-args "--system-initiated"' }
					}
				}
				Stop-Transcript <# Stopping the log #>
			}
			
			Set-UserTeamsPreference -openAsHidden -registerAsIMProvider
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
		Invoke-AsCurrentUser -ScriptBlock $scriptBlock -CacheToDisk -ErrorAction SilentlyContinue
	}
	
	$commandDir = "$env:ProgramFiles\ITMS"
	$commandFile = "Teams-Config-Startup.ps1"
	$triggerName = "Teams Startup At Unlock"
	
	[ScriptBlock]$scriptTaskExists = { }
	[ScriptBlock]$scriptTaskExistsElse = { }
	
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
		Register-ScheduledTask -TaskName $triggerName -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Trigger $onLogin, $onUnlockTrigger -Action $Action -Settings $triggerSettings -Force # Specify the name of the task
	}
	
	Set-CustomScheduledTask
	#Start-ScheduledTask -TaskName $triggerName
}

Run-ScriptBlock
