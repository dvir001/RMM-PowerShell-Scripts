Function cleanTempFolderBrowsersEventLog
{
	
	cleanFolder "User's TEMP" "C:\Users\*\AppData\Local\Temp\*" @("*") $global:RetentionDays $True
	cleanFolder "Temporary Internet Files" "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" @("*") $global:RetentionDays $True
	cleanFolder "Crash Dumps" "C:\Users\*\AppData\Local\CrashDumps\*" @("*") $global:RetentionDays $True
	cleanFolder "Windows Error Reporting" "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" @("*") $global:RetentionDays $True
	cleanFolder "Event Trace Logs and Thumbnails" "C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\*" @(".etl", ".db") $global:RetentionDays $True
	cleanFolder "Internet Explorer" "C:\Users\*\AppData\Local\Microsoft\Internet Explorer\*" @("*") $global:RetentionDays $True
	cleanFolder "Terminal Server cache" "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" @("*") $global:RetentionDays $True
	cleanFolder "Recently used documents and folders" "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*" @(".lnk") $global:RetentionDays $True
	
	cleanFolder "Software Distribution Logfiles" "$Env:windir\SoftwareDistribution\DataStore\Logs\*" @(".log") $global:RetentionDays $True
	cleanFolder "" "$Env:windir\Performance\WinSAT\DataStore\*" @("*") $global:RetentionDays $True
	cleanFolder "Software Distribution logfiles" "$Env:windir\system32\catroot2\*" @(".jrs", ".log") $global:RetentionDays $True
	cleanFolder "Windows Diagnostics Infrastructure logfiles" "$Env:windir\system32\wdi\LogFiles\*" @("*") $global:RetentionDays $True
	cleanFolder "Windows Debug" "$Env:windir\debug\*" @(".log") $global:RetentionDays $True
	cleanFolder "Windows Temp" "$Env:windir\Temp\*" @("*") $global:RetentionDays $True
	cleanFolder "Prefetch" "$Env:windir\Prefetch\*" @("*") $global:RetentionDays $True
	cleanFolder "Windows Error Reporting" "C:\ProgramData\Microsoft\Windows\WER\*" @("*") $global:RetentionDays $True
	
	cleanFolder "" "$Env:windir\logs\CBS\*" @(".log") 0 $True
	cleanFolder "" "C:\inetpub\logs\LogFiles\*" @("*") 0 $True
	
	
	
	removeFile "$Env:windir\memory.dmp" $global:RetentionDays
	removeFile "C:\ProgramData\Microsoft\Windows\Power Efficiency Diagnostics\energy-report-*-*-*.xml" $global:RetentionDays
	
	
	cleanIE_Chrome_Edge_Firefox
	
	clearEventlogs
	
	# -ErrorAction SilentlyContinue needed to suppress error , this is fixed in PS 7
	Clear-RecycleBin -DriveLetter C -Force -Verbose -ErrorAction SilentlyContinue
	dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
	
}

Function cleanWDIfolder
{
	cleanFolder "" "C:\Windows\System32\WDI\*" @("*") 0 $True
}

#
#  functions that clean files, folders, etcetera
#

Function cleanFolder
{
	Param
	(
		[string]$description,
		[string]$folder,
		[string[]]$extensions,
		[int32]$retentionDays,
		[bool]$recursive
	)
	if ($recursive -eq $True)
	{
		$recurse = @{ 'Recurse' = $True }
	}
	else
	{
		$recurse = ""
	}
	
	if (Test-Path "$folder")
	{
		Get-ChildItem "$folder" @recurse -Force -ErrorAction SilentlyContinue |
		Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$retentionDays)) } |
		ForEach-Object {
			if ($extensions -contains $_.Extension)
			{
				Remove-Item $_.FullName -Force -Verbose -ErrorAction SilentlyContinue
			}
			else
			{
				if ($extensions -contains "*")
				{
					Remove-Item $_.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
				}
			}
		}
	}
	else
	{
		Write-Host "$folder does not exist." -ForegroundColor DarkGray
	}
}

Function removeFolder
{
	Param
	(
		[string]$folder
	)
	if (Test-path "$folder")
	{
		Remove-Item "$folder" -Recurse -Force -Verbose -ErrorAction SilentlyContinue
	}
	else
	{
		Write-Host "Folder $folder does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
	}
}

Function removeFile
{
	Param
	(
		[string]$file,
		[int32]$retentionDays
	)
	Get-ChildItem -Path $file -ErrorAction SilentlyContinue |
	Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$retentionDays)) } |
	Remove-Item -ErrorAction SilentlyContinue
}

Function cleanIE_Chrome_Edge_Firefox
{
	
	Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
	Start-Sleep -Seconds 5
	$DaysToDelete = 1
	
	$temporaryIEDir = "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" ## Remove all files and folders in user's Temporary Internet Files. 
	$cachesDir = "C:\Users\*\AppData\Local\Microsoft\Windows\Caches" ## Remove all IE caches. 
	$cookiesDir = "C:\Documents and Settings\*\Cookies\*" ## Delets all cookies. 
	$locSetDir = "C:\Documents and Settings\*\Local Settings\Temp\*" ## Delets all local settings temp 
	$locSetIEDir = "C:\Documents and Settings\*\Local Settings\Temporary Internet Files\*" ## Delets all local settings IE temp 
	$locSetHisDir = "C:\Documents and Settings\*\Local Settings\History\*" ## Delets all local settings history
	
	Get-ChildItem $temporaryIEDir, $cachesDir, $cookiesDir, $locSetDir, $locSetIEDir, $locSetHisDir -Recurse -Force -Verbose -ErrorAction SilentlyContinue | Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } | remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
	
	$DaysToDelete = 7
	
	$crLauncherDir = "C:\Documents and Settings\%USERNAME%\Local Settings\Application Data\Chromium\User Data\Default"
	$chromeDir = "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default"
	$chromeSetDir = "C:\Users\*\Local Settings\Application Data\Google\Chrome\User Data\Default"
	
	$Items = @("*Archived History*", "*Cache*", "*Cookies*", "*History*", "*Login Data*", "*Top Sites*", "*Visited Links*", "*Web Data*")
	
	$items | ForEach-Object {
		$item = $_
		Get-ChildItem $crLauncherDir, $chromeDir, $chromeSetDir -Recurse -Force -ErrorAction SilentlyContinue |
		Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_ -like $item } | ForEach-Object -Process { Remove-Item $_ -force -Verbose -recurse -ErrorAction SilentlyContinue }
	}
	
	$DaysToDelete = 3
	
	#	$crLauncherDir = "C:\Documents and Settings\%USERNAME%\Local Settings\Application Data\Chromium\User Data\Default"
	$edgeDir = "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default"
	$edgeSetDir = "C:\Users\*\Local Settings\Application Data\Microsoft\Edge\User Data"
	
	$Items = @("*Archived History*", "*Cache*", "*Cookies*", "*History*", "*Login Data*", "*Top Sites*", "*Visited Links*", "*Web Data*")
	
	$items | ForEach-Object {
		$item = $_
		Get-ChildItem $edgeDir, $edgeSetDir -Recurse -Force -ErrorAction SilentlyContinue |
		Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_ -like $item } | ForEach-Object -Process { Remove-Item $_ -force -Verbose -recurse -ErrorAction SilentlyContinue }
	}
	
	$DaysToDelete = 1
	
	#	$crLauncherDir = "C:\Documents and Settings\%USERNAME%\Local Settings\Application Data\Chromium\User Data\Default"
	$firefoxDir = "C:\Users\*\AppData\Local\Mozilla\Firefox\"
	#	$firefoxSetDir = "C:\Users\*\Local Settings\Application Data\Microsoft\Edge\User Data"
	
	$Items = @("*cache2*")
	
	$Items | ForEach-Object {
		$item = $_
		Get-ChildItem $firefoxDir -Recurse -Force -ErrorAction SilentlyContinue |
		Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_ -like $item } | ForEach-Object -Process { Remove-Item $_ -force -Verbose -recurse -ErrorAction SilentlyContinue }
	}
}

Function cleanWindowsStore
{
	wsreset
}

Function clearEventlogs
{
	wevtutil el | Foreach-Object { Write-Progress -Activity "Clearing events" -Status " $_"; try { wevtutil cl "$_" 2> $null }
		catch { } }
	Write-Progress -Activity "Done" -Status "Done" -Completed
}

Function WindowsDiskCleaner
{
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

Function cleanSoftwareDistribution
{
	## Stops the windows update service so that c:\windows\softwaredistribution can be cleaned up
	Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
	Get-Service -Name bits | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
	## Deletes the contents of windows software distribution.
	Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -recurse -ErrorAction SilentlyContinue -Verbose
	## Restarts wuauserv and bits services
	Get-Service -Name wuauserv | Start-Service -ErrorAction SilentlyContinue -Verbose
	Get-Service -Name bits | Start-Service -ErrorAction SilentlyContinue -Verbose
}

Function cleanCatroot2
{
	Get-Service -Name cryptsvc | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
	Copy-Item "C:\Windows\System32\Catroot2" "C:\Windows\System32\Catroot2.old" -force -recurse -verbose
	Get-ChildItem "C:\Windows\System32\Catroot2\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -recurse -ErrorAction SilentlyContinue -Verbose
	Get-Service -Name cryptsvc | Start-Service -ErrorAction SilentlyContinue -Verbose
}

cleanTempFolderBrowsersEventLog
cleanWDIfolder
cleanIE_Chrome_Edge_Firefox
cleanWindowsStore
clearEventlogs
WindowsDiskCleaner
cleanSoftwareDistribution
cleanCatroot2

