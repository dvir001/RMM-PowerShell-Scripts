function Program-Install
{
	param (
		[string]$installSource,
		[string]$installName,
		[string]$installArgument,
		[string]$installTest,
		[string]$workDir,
		[string]$maxLoop,
		[switch]$disableStartProcess = $true,
		[switch]$deleteInstallSource = $true
	)
	
	if ([string]::IsNullOrEmpty($maxLoop)) { $maxLoop = "5" } <# Loop max #>
	$sleepTimer = "5" <# Sleep before next loop #>
	
	if ((Test-Path -Path $installTest) -ne "True")
	{
		if ((Test-Path -Path "$workDir\$installName") -ne "True") <# Lookup if the exe is there #>
		{
			if (Get-Command 'Invoke-Webrequest') { Invoke-WebRequest $installSource -OutFile "$workDir\$installName" | Wait-Job }
			else
			{
				$WebClient = New-Object System.Net.WebClient
				$webclient.DownloadFile($installSource, "$workDir\$installName")
			}
		}
		
		[int]$retryCount = "0" <# Loop starting at 0 #>
		[int]$retryCountMax = $maxLoop <# Try max loops #>
		$stopLoop = $false <# Base status for looping, stoping loop when True #>
		
		if ($disableStartProcess)
		{
			do <# Install and verify #>
			{
				if ((Test-Path -Path $installTest) -eq "True")
				{
					Write-Host "$installName installed!"
					Start-Sleep -Seconds $sleepTimer
					$stopLoop = $true
				}
				if ((Test-Path -Path $installTest) -ne "True")
				{
					if ([int]$retrycount -eq "0")
					{
						Write-Host "Running $installName install..."
						Start-Process -FilePath "$workDir\$installName" -ArgumentList $installArgument -Wait <# Run the exe #>
					}
					$Retrycount = $Retrycount + 1
					if ($Retrycount -gt $RetrycountMax)
					{
						Write-Host "$installName failed to install..."
						$stopLoop = $true
					}
					else
					{
						Write-Host "Testing $installName Install, attempt number $retryCount, Waiting $sleepTimer secs..."
						Start-Sleep -Seconds $sleepTimer
					} <# Sleep before next loop #>
				}
			}
			While ($stopLoop -eq $false)
		}
	}
	if ($deleteInstallSource)
	{
		if ((Test-Path -Path "$workDir\$installName") -eq "True") { Remove-Item -Path "$workDir\$installName" -Force -Recurse }
	}
}

function Program-Run
{
	param (
		[string]$installName,
		[string]$installArgument,
		[string]$installTest,
		[string]$workDir,
		[switch]$deleteInstallSource = $true
	)
	
	if ([string]::IsNullOrEmpty($maxLoop)) { $maxLoop = "5" } <# Loop max #>
	$sleepTimer = "5" <# Sleep before next loop #>
	
	if ((Test-Path -Path $installTest) -ne "True")
	{
		[int]$retryCount = "0" <# Loop starting at 0 #>
		[int]$retryCountMax = $maxLoop <# Try max loops #>
		$stopLoop = $false <# Base status for looping, stoping loop when True #>
		
		do <# Install and verify #>
		{
			if ((Test-Path -Path $installTest) -eq "True")
			{
				Write-Host "$installName installed!"
				Start-Sleep -Seconds $sleepTimer
				$stopLoop = $true
			}
			if ((Test-Path -Path $installTest) -ne "True")
			{
				if ([int]$retrycount -eq "0")
				{
					Write-Host "Running $workDir\$installName install..."
					if ([string]::IsNullOrEmpty($installArgument)) <# Run the exe #>
					{ Start-Process -FilePath "$workDir\$installName" -Wait }
					else
					{ Start-Process -FilePath "$workDir\$installName" -ArgumentList $installArgument -Wait }
				}
				$Retrycount = $Retrycount + 1
				if ($Retrycount -gt $RetrycountMax)
				{
					Write-Host "$workDir\$installName failed to install..."
					$stopLoop = $true
				}
				else
				{
					Write-Host "Testing $workDir\$installName Install, attempt number $retryCount, Waiting $sleepTimer secs..."
					Start-Sleep -Seconds $sleepTimer
				} <# Sleep before next loop #>
			}
		}
		While ($stopLoop -eq $false)
	}
	if ($deleteInstallSource)
	{
		if ((Test-Path -Path "$workDir\$installFolder") -eq "True") { Remove-Item -Path "$workDir\$installFolder" -Force -Recurse }
	}
}

function Drivers-Install
{
	$PCInfo = Get-WMIObject -Query "Select * from Win32_ComputerSystem" | Select-Object -Property Manufacturer, Model
	$PCmanufacturer = $PCInfo.Manufacturer
	
	if ($PCmanufacturer -like "*DELL*") <# Locate Dell PC Manufacturer #>
	{
		$installFolder = "Dell-Power-Manager"
		Program-Install -installSource "https://dl.dell.com/FOLDER05695265M/3/Dell-Power-Manager-Service_H2VH9_WIN64_3.4.0_A00_01.EXE" -installName "$installFolder.exe" -installArgument "/s /e=$env:windir\Temp\$installFolder" -installTest "$env:windir\Temp\$installFolder\DPM_Setup64*" -workDir "$env:windir\Temp"
		Program-Run -installName "$installFolder\DPM_Setup64_3_4_0.exe" -installArgument "/S /v/qn" -installTest "$env:ProgramFiles\Dell\CommandPowerManager\BatteryExtenderUtil.exe" -workDir "$env:windir\Temp"
		
		$installFolder = "Dell-Command-Update-Application"
		Program-Install -installSource "https://dl.dell.com/FOLDER07414743M/2/Dell-Command-Update-Application_XM3K1_WIN_4.2.1_A00.EXE" -installName "$installFolder.exe" -installArgument "/s /e=$env:windir\Temp\$installFolder" -installTest "$env:windir\Temp\$installFolder\DCU_Setup*" -workDir "$env:windir\Temp"
		Program-Run -installName "$installFolder\DCU_Setup_4_2_1.exe" -installArgument "/S /v/qn" -installTest "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe" -workDir "$env:windir\Temp"
		
		try { Import-Module DellBIOSProvider -ErrorAction Stop }
		catch
		{
			Write-Host "Could not find DellBIOSProvider, Installing..."
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose:$false *>$null
			Install-Module -Name DellBIOSProvider -Scope AllUsers -force
			Import-Module DellBIOSProvider -ErrorAction Stop
		}
		Set-Item -Path DellSmbios:\TpmSecurity\TpmSecurity "Enabled" -ErrorAction SilentlyContinue
		Set-Item -Path DellSmbios:\TpmSecurity\TPMActivation "Enabled" -ErrorAction SilentlyContinue
		
		Write-host "Updating Dell Drivers..."
		Start-Process -FilePath "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/ApplyUpdates -reboot=disable" -Wait
	}
	
	if ($PCmanufacturer -like "*LENOVO*") <# Locate Lenovo PC Manufacturer #>
	{
		Write-host "Updating Lenovo Drivers..."
		Program-Install -installSource "https://download.lenovo.com/consumer/options/lenovo_thinkpad_thunderbolt_3_dock_and_usb_c_dock_driver_v10019.exe" -installName "lenovo_dock_driver.exe" -installArgument "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -installTest "${env:ProgramFiles(x86)}\Lenovo\Thinkpad USB Ethernet Adapter Driver\RTINSTALLER64.EXE" -workDir "$env:windir\Temp" -StartProcess
		
		[ScriptBlock]$updateLenovoDrivers = {
			try { Import-Module LSUClient -ErrorAction Stop }
			catch
			{
				Write-Host "Could not find LSUClient, Installing..."
				Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose:$false *>$null
				Install-Module -Name LSUClient -Scope AllUsers -force
				Import-Module LSUClient -ErrorAction Stop
			}
			
			#Get-AppxProvisionedPackage -Online | Where-Object { $_.name -like '*len*' }
			#Get-AppxPackage | Where-Object { $_.PackageFullName -like '*len*' }
			
			$updateLenovo = Get-LSUpdate | Where-Object { $_.Installer.Unattended }
			$updateLenovo | Save-LSUpdate -Verbose
			$updateLenovo | Install-LSUpdate -Verbose
		}
		try { Invoke-AsCurrentUser -ScriptBlock $updateLenovoDrivers -CacheToDisk -ErrorAction Stop } <# Run as user #>
		catch { Invoke-Command -Command $updateLenovoDrivers }
		
		# Get all BIOS settings (for reference)
		# Get-WmiObject -class Lenovo_BiosSetting -namespace root\wmi | ForEach-Object {if ($_.CurrentSetting -ne "") {Write-Host $_.CurrentSetting.replace(","," = ")}}
		
		$Model = Get-WmiObject -Class Win32_ComputerSystemProduct
		
		if ($Model.version.TrimEnd() -like "*ThinkPad*") <# Laptop #>
		{
			(Get-WmiObject -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting("SecurityChip,Active") <# Enable TPM #>
			(Get-WmiObject -class Lenovo_SaveBiosSettings -namespace root\wmi).SaveBiosSettings() <# Save settings #>
		}
		
		if ($Model.version.TrimEnd() -like "*ThinkCentre*") <# Desktop #>
		{
			(Get-WmiObject -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting("TCG Security Feature,Active") <# Enable TPM #>
			(Get-WmiObject -class Lenovo_SaveBiosSettings -namespace root\wmi).SaveBiosSettings() <# Save settings #>
		}
	}
	
	if (($PCmanufacturer -like "*HEWLETT*") -or ($PCmanufacturer -like "*HP*")) <# Locate HP PC Manufacturer #>
	{
		Write-host "Updating HP Drivers..."
		
		# Install HP-HPIA
		$installFolder = "HP-HPIA"
		$installTest = "$env:windir\Temp\$installFolder"
		$installArgument = '/s /e /f ' + $installTest
		Program-Install -installSource "https://hpia.hpcloud.hp.com/downloads/hpia/hp-hpia-5.1.2.exe" -installName "$installFolder.exe" -installArgument $installArgument -installTest $installTest -workDir "$env:windir\Temp"
		Program-Run -installName "$installFolder\ImageAssistant.exe" -installArgument '/Operation:Analyze /Category:All /Selection:All /Action:Install /SoftpaqDownloadFolder:"C:\Windows\Temp\HP-HPIA\Downloads" /Silent' -installTest "$env:windir\Temp\$installFolder\Downloads\fake.old" -workDir "$env:windir\Temp" -deleteInstallSource:$false
		
		# Install HP-SA
		Program-Install -installSource "https://ftp.ext.hp.com/pub/softpaq/sp123001-123500/sp123485.exe" -installName "HP-SA.exe" -installArgument "/s" -installTest "${env:ProgramFiles(x86)}\HP\HP Support Framework\TaskbarController.exe" -workDir "$env:windir\Temp" -disableStartProcess:$false
		[ScriptBlock]$scriptBlock = { Start-Process -FilePath "$env:windir\Temp\HP-SA.exe" -ArgumentList "/s" -Wait }
		try { Invoke-AsCurrentUser -ScriptBlock $scriptBlock -CacheToDisk -ErrorAction Stop } <# Run program #>
		catch { Invoke-Command -Command $scriptBlock }
		
		# Install HP-BCU
		$installFolder = "HP-BCU"
		$installTest = "$env:windir\Temp\$installFolder"
		$installArgument = '/s /e /f ' + $installTest
		Program-Install -installSource "https://ftp.ext.hp.com/pub/softpaq/sp107501-108000/sp107705.exe" -installName "$installFolder.exe" -installArgument $installArgument -installTest $installTest -workDir "$env:windir\Temp"
		Program-Run -installName "$installFolder\Setup.exe" -installArgument "/S /v/qn" -installTest "${env:ProgramFiles(x86)}\HP\BIOS Configuration Utility\BiosConfigUtility.exe" -workDir "$env:windir\Temp"
	}
}

function RunAsUser-Install
{
	try { Import-Module RunAsUser -ErrorAction Stop }
	catch
	{
		Write-Host "Could not find RunAsUser, Installing..."
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose:$false *>$null
		Install-Module -Name RunAsUser -Scope AllUsers -force
		Import-Module RunAsUser -ErrorAction Stop
	}
}

RunAsUser-Install
Drivers-Install
