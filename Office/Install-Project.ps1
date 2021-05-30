# Install Visio
function Install-Project
{			
	# Config:
	$exeSource = 'https://github.com/dvir001/Pulseway-PowerShell-Scripts/releases/download/Office/setup.exe'
	$configSource = 'https://github.com/dvir001/Pulseway-PowerShell-Scripts/releases/download/Office/O365Project-EN_HE.xml'
	$configName = 'O365Project-EN_HE.xml'
	
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
}

# Add shortcuts on desktop
function Set-Shortcuts
{
	$Officepath = (New-Object -ComObject WScript.Shell).RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Winword.exe\Path")
	$Profiles = Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.GetValue('ProfileImagePath') }
	
	foreach ($profile in $profiles -match "Users" -notmatch "spfarm" -notmatch "spsearch" -notmatch "TEMP" -notmatch "Classic")
	{
		$WshShell = New-Object -comObject WScript.Shell
		$Shortcut = $WshShell.CreateShortcut("$Profile\Desktop\Project.lnk")
		$Shortcut.TargetPath = "$Officepath\WINPROJ.exe"
		$Shortcut.Save()
	}
}

# Run Commands
Install-Project
Set-Shortcuts