$PCInfo = Get-WMIObject -Query "Select * from Win32_ComputerSystem" | Select-Object -Property Manufacturer, Model

# Locate Dell PC Manufacturer
if ($PCInfo.Manufacturer -like "*DELL*")
{
	$source = 'https://dl.dell.com/FOLDER06986472M/1/Dell-Command-Update-Application-for-Windows-10_DF2DT_WIN_4.1.0_A00.EXE'
	$exeDir = 'C:\Windows\Temp'
	$exeName = 'Dell-Command-Update-Application-for-Windows-10_DF2DT_WIN_4.1.0_A00.EXE'
	$ArgumentList = '/s'
	
	$exeLocation = $exeDir + '\' + $exeName
	
	if ((Test-Path $exeLocation) -ne "True") { Invoke-WebRequest $source -OutFile $exeLocation | Wait-Job } <# Lookup if the exe is there #>
	
	Start-Process -FilePath $exeLocation -ArgumentList $ArgumentList | Wait-Job
	
	$32bit = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
	$32bitLocation = Test-Path $32bit
	$64bit = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
	$64bitLocation = Test-Path $64bit
	
	If ($32bitLocation -eq "True")
	{
		Write-host "Updating Dell Drivers..."
		Start-Process -FilePath $32bit -ArgumentList "/ApplyUpdates -reboot=disable"
	}
	If ($64bitLocation -eq "True")
	{
		Write-host "Updating Dell Drivers..."
		Start-Process -FilePath $64bit -ArgumentList "/ApplyUpdates -reboot=disable"
	}
	
	If (($32bitLocation -eq "False") -and ($64bitLocation -eq "False")) { Write-host 'Script failed to run "dcu-cli.exe" as the program was not found.' }
}

# Locate Lenovo PC Manufacturer
if ($PCInfo.Manufacturer -like "*LENOVO*")
{
	Write-host "Updating Lenovo Drivers..."
	Install-Module -Name LSUClient -Force
    Import-Module -Name LSUClient -Force
	$updates = Get-LSUpdate | Where-Object { $_.Installer.Unattended }
	$updates | Save-LSUpdate -Verbose
	$updates | Install-LSUpdate -Verbose
}

