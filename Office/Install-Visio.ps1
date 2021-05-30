# Install Visio
function Install-Visio
{			
	# Config:
	$exeSource = 'https://github.com/dvir001/Pulseway-PowerShell-Scripts/releases/download/Office/setup.exe'
	$configSource = 'https://github.com/dvir001/Pulseway-PowerShell-Scripts/releases/download/Office/O365Visio-EN_HE.xml'
	$configName = 'O365Visio-EN_HE.xml'
	
	# Static Config:
	$exeName = 'setup.exe'
	$dir = 'C:\Windows\Temp'
	$ArgumentList = '/configure'
	
	$exeLocation = $dir + '\' + $exeName
	$configLocation = $dir + '\' + $configName
	
	if ((Test-Path $exeLocation) -ne "True") { Invoke-WebRequest $exeSource -OutFile $exeLocation } <# Lookup if the exe is there #>
	if ((Test-Path $configLocation) -ne "True") { Invoke-WebRequest $configSource -OutFile $configLocation } <# Lookup if the config xml is there #>
	
	# Run the install
	Invoke-Expression -Command "$exeLocation $ArgumentList $configLocation"
	# C:\ProgramData\chocolatey\choco.exe install office365business -y --acceptlicense --params=/language:"en-US" /updates:"TRUE" /eula:"TRUE" <# Old choco install line #>
}

# Add shortcuts on desktop
function Set-Shortcuts
{
	$Officepath = (New-Object -ComObject WScript.Shell).RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Winword.exe\Path")
	$Profiles = Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.GetValue('ProfileImagePath') }
	
	foreach ($profile in $profiles -match "Users" -notmatch "spfarm" -notmatch "spsearch" -notmatch "TEMP" -notmatch "Classic")
	{
		$WshShell = New-Object -comObject WScript.Shell
		$Shortcut = $WshShell.CreateShortcut("$Profile\Desktop\Visio.lnk")
		$Shortcut.TargetPath = "$Officepath\Visio.exe"
		$Shortcut.Save()
	}
}

# Run Commands
Install-Visio
Set-Shortcuts