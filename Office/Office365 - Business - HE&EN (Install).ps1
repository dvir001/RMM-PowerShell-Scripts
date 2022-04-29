$configContent = @'
<Configuration ID="3f35603a-e295-4fd4-a9f2-db889e440a17">
  <Add OfficeClientEdition="64" Channel="SemiAnnual" MigrateArch="TRUE">
    <Product ID="O365BusinessRetail">
      <Language ID="he-il" />
      <Language ID="en-us" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
    </Product>
    <Product ID="LanguagePack">
      <Language ID="he-il" />
      <Language ID="en-us" />
    </Product>
    <Product ID="ProofingTools">
      <Language ID="he-il" />
      <Language ID="en-us" />
    </Product>
  </Add>
  <Property Name="SCLCacheOverride" Value="0" />
  <Property Name="AUTOACTIVATE" Value="0" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
  <Updates Enabled="TRUE" />
  <AppSettings>
    <User Key="software\microsoft\office\16.0\excel\options" Name="defaultformat" Value="51" Type="REG_DWORD" App="excel16" Id="L_SaveExcelfilesas" />
    <User Key="software\microsoft\office\16.0\powerpoint\options" Name="defaultformat" Value="27" Type="REG_DWORD" App="ppt16" Id="L_SavePowerPointfilesas" />
    <User Key="software\microsoft\office\16.0\word\options" Name="defaultformat" Value="" Type="REG_SZ" App="word16" Id="L_SaveWordfilesas" />
  </AppSettings>
  <Display Level="None" AcceptEULA="TRUE" />
</Configuration>
'@

$InstallParameters = @{
	installSource = "https://github.com/dvir001/RMM-PowerShell-Scripts/raw/main/FilesForScripts/setup.exe" <# Download link for exe #>
	configFile    = "O365Office.xml"
	configContent = $configContent
	installZip    = ""
	installName   = "setup.exe"
	zipDir	      = ""
	unzipDir	  = ""
	installDir    = "$env:windir\Temp"
	installTests  = "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE", "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE", "$env:ProgramFiles\Microsoft Office\Office16\OUTLOOK.EXE", "${env:ProgramFiles(x86)}\Microsoft Office\Office16\OUTLOOK.EXE", "$env:ProgramFiles\Microsoft Office\Office15\OUTLOOK.EXE", "${env:ProgramFiles(x86)}\Microsoft Office\Office15\OUTLOOK.EXE"
	installArgument = "Start-Process -FilePath `"$env:windir\Temp\setup.exe`" -ArgumentList `'/configure `"$env:windir\Temp\O365Office.xml`"`' -Wait -Verbose -ErrorAction Ignore"
	cleanFilesOnExit = $true
	sleepTimer    = "5"
	retryCountMax = "5"
	brokenTestMax = "5" <# Max tests before the script closing from a broken loop #>
}

function Install-Program
{
	<#
	.SYNOPSIS
		Version 1.1

	.DESCRIPTION
		Smart install programs script, multi options.

	.EXAMPLE
	$InstallParameters = @{
		installSource = "URL"
		configFile    = "O365Office.xml"
		configContent = $configContent
		installZip    = ""
		installName   = "setup.exe"
		zipDir	      = ""
		unzipDir	  = ""
		installDir    = "$env:windir\Temp"
		installTests  = "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE", "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE", "$env:ProgramFiles\Microsoft Office\Office16\OUTLOOK.EXE", "${env:ProgramFiles(x86)}\Microsoft Office\Office16\OUTLOOK.EXE", "$env:ProgramFiles\Microsoft Office\Office15\OUTLOOK.EXE", "${env:ProgramFiles(x86)}\Microsoft Office\Office15\OUTLOOK.EXE"
		installArgument = "Start-Process -FilePath `"$env:windir\Temp\setup.exe`" -ArgumentList `'/configure `"$env:windir\Temp\O365Office.xml`"`' -Wait -Verbose -ErrorAction Ignore"
		cleanFilesOnExit = $true
		sleepTimer    = "5"
		retryCountMax = "5"
		brokenTestMax = "5"
	}
	
	Install-Program @InstallParameters
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[uri]$installSource,
		[Parameter(Mandatory = $false)]
		[String]$configFile,
		[Parameter(Mandatory = $false)]
		[String]$configContent,
		[Parameter(Mandatory = $false)]
		[String]$installZip,
		[Parameter(Mandatory = $false)]
		[String]$installName,
		[Parameter(Mandatory = $false)]
		[String]$zipDir,
		[Parameter(Mandatory = $false)]
		[String]$unzipDir,
		[Parameter(Mandatory = $false)]
		[String]$installDir,
		[Parameter(Mandatory = $false)]
		[Array]$installTests,
		[Parameter(Mandatory = $false)]
		[String]$installArgument,
		[Parameter(Mandatory = $true)]
		[Switch]$cleanFilesOnExit,
		[Parameter(Mandatory = $true)]
		[int]$sleepTimer,
		[Parameter(Mandatory = $false)]
		[int]$retryCountMax,
		[Parameter(Mandatory = $true)]
		[int]$brokenTestMax
	)
	
	[Switch]$loop = $true <# Base loop, do not change #>
	[int]$retryCount = "0" <# Loop starting at 0, do not change #>
	[int]$brokenTest = "0" <# Test starting at 0, do not change #>
	[Switch]$startInstall = $true <# Base status, do not change #>
	[Switch]$skipFailTest = $false
	if (([int]$retryCountMax -eq "0") -or (([string]::IsNullOrEmpty($retryCountMax)))) { [Switch]$skipFailTest = $true }
	
	if (!([string]::IsNullOrEmpty($installTests)))
	{ foreach ($installTest in $installTests) { if (Test-Path -Path $installTest) { [Switch]$startInstall = $false; break } } <# Test for install #> }
	else
	{
		[Switch]$startInstall = $true
		$installTest = $false
		$skipFailTest = $true
	}
	
	function Create-Folders
	{
		[CmdletBinding()]
		param (
			[Parameter(Position = 0, Mandatory = $true)]
			[System.Array]$folders
		)
		
		foreach ($folder in $folders)
		{ if (!([System.IO.Directory]::Exists($folder))) { New-Item $folder -ItemType Directory | Out-Null } } <# Create directory if not exists #>
	}
	
	if (!([string]::IsNullOrEmpty($unzipDir))) { [System.Array]$foldersArray += $unzipDir }
	if (!([string]::IsNullOrEmpty($zipDir))) { [System.Array]$foldersArray += $zipDir }
	if (!([string]::IsNullOrEmpty($installDir))) { [System.Array]$foldersArray += $installDir }
	Create-Folders -Folders $foldersArray
	
	if ([Switch]$startInstall)
	{
		do <# Install and verify #>
		{
			function Clean-InstallFiles
			{
				if (!([string]::IsNullOrEmpty($zipDir)))
				{
					if (Test-Path -Path "$zipDir\$installZip") { Remove-Item -Path "$zipDir\$installZip" -Force -Verbose -ErrorAction SilentlyContinue }
					if (Test-Path -Path "$installDir") { Remove-Item -Path "$installDir" -Recurse -Force -Verbose -ErrorAction SilentlyContinue }
				}
				else
				{
					if (Test-Path -Path "$installDir\$installName") { Remove-Item -Path "$installDir\$installName" -Force -Verbose -ErrorAction SilentlyContinue }
				}
				if (!([string]::IsNullOrEmpty($configFile)))
				{
					If (Test-Path "$installDir\$configFile") { Remove-Item -Path "$installDir\$configFile" -Force -Verbose -ErrorAction SilentlyContinue }
				}
			}
			
			if (!(Test-Path -Path $installTest)) <# Download & Unzip block #>
			{
				if ([int]$retryCount -eq "0")
				{
					$retryCount += 1
					if (!([string]::IsNullOrEmpty($installZip))) <# Download block #>
					{
						if (!(Test-Path -Path "$zipDir\$installZip")) <# Lookup if the zip is there, Download #>
						{
							Write-Verbose "Downloading to `"$zipDir\$installZip`""
							try { Invoke-WebRequest $installSource -OutFile "$zipDir\$installZip" -Verbose -ErrorAction Ignore | Wait-Job }
							catch [System.Net.WebException]
							{
								Write-Output "Link Broken / No network."
								exit
							}
						}
						
						If (Test-Path -Path "$zipDir\$installZip") <# Unzip block #>
						{
							$ErrorOccured = $false
							try { Expand-Archive -Path "$zipDir\$installZip" -DestinationPath "$unzipDir" -Force -Verbose -ErrorAction Ignore }
							catch
							{
								Write-Output "The zip `"$zipDir\$installZip`" is broken, downloading again..."
								Clean-InstallFiles
								$retryCount -= 1
								$ErrorOccured = $true
							}
						}
					}
					else
					{
						if (!(Test-Path -Path "$installName")) <# Lookup if the file is there, Download #>
						{
							Write-Verbose "Downloading to `"$installDir\$installName`""
							try { Invoke-WebRequest $installSource -OutFile "$installDir\$installName" -Verbose -ErrorAction Ignore | Wait-Job }
							catch [System.Net.WebException] <# This catch is here in case of a dead link, if you get this error the link is either dead or broken. #>
							{
								Write-Output "Link Broken / No network."
								exit
							}
						}
					}
					if (!($ErrorOccured)) <# Run install block #>
					{
						
						if (!([string]::IsNullOrEmpty($configFile)) -and (!([string]::IsNullOrEmpty($configFile))))
						{ New-Item -Path $installDir -Name $configFile -ItemType "file" -Value $configContent -Force -Verbose }
						
						if (!([string]::IsNullOrEmpty($installArgument))) <# If installArgument is empty there is nothing to install, skip. #>
						{
							Write-Output "Running install.."
							Write-Output "Command: `"$installArgument`""
							try { Invoke-Expression -Command $installArgument }
							catch
							{
								Write-Output "The file `"$installDir\$installName`" is broken, downloading again..."
								Clean-InstallFiles
								$retryCount -= 1
							}
						}
					}
				}
			}
			
			if (!($skipFailTest))
			{
				foreach ($installTest in $installTests) { if (Test-Path -Path $installTest) { break } } <# Test for install #>
				
				if (Test-Path -Path $installTest)
				{
					Write-Output "Installed!"
					if ([Switch]$cleanFilesOnExit) { Clean-InstallFiles }
					[Switch]$loop = $false
				}
				
				if (!(Test-Path -Path $installTest))
				{
					if ($retryCount -gt $retryCountMax)
					{
						Write-Output "Failed to install..."
						Clean-InstallFiles
						[Switch]$loop = $false
					}
					elseif ([int]$retryCount -eq "0")
					{
						#Write-Output "Test"
					} <# Do nothing #>
					else
					{
						Write-Output "Testing install, attempt number $retryCount, Waiting $sleepTimer secs..."
						Start-Sleep -Seconds $sleepTimer
						$retryCount += 1
					} <# Sleep before next loop #>
				}
			}
			else { [Switch]$loop = $false }
			
			$brokenTest += 1 <# If this loop hits $brokenTestMax the script will stop. #>
			if ($brokenTest -gt $brokenTestMax)
			{
				Write-Output "The script is broken, closing."
				exit
			}
		}
		While ($loop)
	}
	else
	{
		Write-Output "The program is already installed on this machine"
	}
}

function Set-Default
{
	[ScriptBlock]$default = {
		
		$defaults = @(
			@{
				command   = "Set-PTA"
				program   = "Outlook.URL.mailto.15"
				extension = "mailto"
			} <# Outlook #>
		)
		
		function Get-FTA
		{
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $false)]
				[String]$Extension
			)
			
			
			if ($Extension)
			{
				Write-Verbose "Get File Type Association for $Extension"
				
				$assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -ErrorAction SilentlyContinue).ProgId
				Write-Output $assocFile
			}
			else
			{
				Write-Verbose "Get File Type Association List"
				
				$assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\* |
				ForEach-Object {
					$progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
					if ($progId)
					{
						"$($_.PSChildName), $progId"
					}
				}
				Write-Output $assocList
			}
			
		}
		
		function Get-PTA
		{
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $false)]
				[String]$Protocol
			)
			
			if ($Protocol)
			{
				Write-Verbose "Get Protocol Type Association for $Protocol"
				
				$assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice" -ErrorAction SilentlyContinue).ProgId
				Write-Output $assocFile
			}
			else
			{
				Write-Verbose "Get Protocol Type Association List"
				
				$assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\* |
				ForEach-Object {
					$progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
					if ($progId)
					{
						"$($_.PSChildName), $progId"
					}
				}
				Write-Output $assocList
			}
		}
		
		function Register-FTA
		{
			[CmdletBinding()]
			param (
				[Parameter(Position = 0, Mandatory = $true)]
				[ValidateScript({ Test-Path $_ })]
				[String]$ProgramPath,
				[Parameter(Position = 1, Mandatory = $true)]
				[Alias("Protocol")]
				[String]$Extension,
				[Parameter(Position = 2, Mandatory = $false)]
				[String]$ProgId,
				[Parameter(Position = 3, Mandatory = $false)]
				[String]$Icon
			)
			
			Write-Verbose "Register Application + Set Association"
			Write-Verbose "Application Path: $ProgramPath"
			if ($Extension.Contains("."))
			{
				Write-Verbose "Extension: $Extension"
			}
			else
			{
				Write-Verbose "Protocol: $Extension"
			}
			
			if (!$ProgId)
			{
				$ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
			}
			
			$progCommand = """$ProgramPath"" ""%1"""
			Write-Verbose "ApplicationId: $ProgId"
			Write-Verbose "ApplicationCommand: $progCommand"
			
			try
			{
				$keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$Extension\OpenWithProgids"
				[Microsoft.Win32.Registry]::SetValue($keyPath, $ProgId, ([byte[]]@()), [Microsoft.Win32.RegistryValueKind]::None)
				$keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\shell\open\command"
				[Microsoft.Win32.Registry]::SetValue($keyPath, "", $progCommand)
				Write-Verbose "Register ProgId and ProgId Command OK"
			}
			catch
			{
				throw "Register ProgId and ProgId Command FAIL"
			}
			
			Set-FTA -ProgId $ProgId -Extension $Extension -Icon $Icon
		}
		
		function Remove-FTA
		{
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[Alias("ProgId")]
				[String]$ProgramPath,
				[Parameter(Mandatory = $true)]
				[String]$Extension
			)
			
			function local:Remove-UserChoiceKey
			{
				param (
					[Parameter(Position = 0, Mandatory = $True)]
					[String]$Key
				)
				
				$code = @"
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Win32;
    
    namespace Registry {
      public class Utils {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
    
        [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
        private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);
        public static void DeleteKey(string key) {
          UIntPtr hKey = UIntPtr.Zero;
          RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
          RegDeleteKey((UIntPtr)0x80000001u, key);
        }
      }
    }
"@
				
				try
				{
					Add-Type -TypeDefinition $code
				}
				catch { }
				
				try
				{
					[Registry.Utils]::DeleteKey($Key)
				}
				catch { }
			}
			
			function local:Update-Registry
			{
				$code = @"
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
"@
				
				try
				{
					Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
				}
				catch { }
				
				try
				{
					[SHChange.Notify]::Refresh()
				}
				catch { }
			}
			
			if (Test-Path -Path $ProgramPath)
			{
				$ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
			}
			else
			{
				$ProgId = $ProgramPath
			}
			
			try
			{
				$keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
				Write-Verbose "Remove User UserChoice Key If Exist: $keyPath"
				Remove-UserChoiceKey $keyPath
				
				$keyPath = "HKCU:\SOFTWARE\Classes\$ProgId"
				Write-Verbose "Remove Key If Exist: $keyPath"
				Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
				
			}
			catch
			{
				Write-Verbose "Key No Exist: $keyPath"
			}
			
			try
			{
				$keyPath = "HKCU:\SOFTWARE\Classes\$Extension\OpenWithProgids"
				Write-Verbose "Remove Property If Exist: $keyPath Property $ProgId"
				Remove-ItemProperty -Path $keyPath -Name $ProgId -ErrorAction Stop | Out-Null
				
			}
			catch
			{
				Write-Verbose "Property No Exist: $keyPath Property: $ProgId"
			}
			
			Update-Registry
			Write-Output "Removed: $ProgId"
		}
		
		function Set-FTA
		{
			
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[String]$ProgId,
				[Parameter(Mandatory = $true)]
				[Alias("Protocol")]
				[String]$Extension,
				[String]$Icon
			)
			
			if (Test-Path -Path $ProgId)
			{
				$ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
			}
			
			Write-Verbose "ProgId: $ProgId"
			Write-Verbose "Extension/Protocol: $Extension"
			
			
			function local:Update-RegistryChanges
			{
				$code = @"
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
"@
				
				try
				{
					Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
				}
				catch { }
				
				try
				{
					[SHChange.Notify]::Refresh()
				}
				catch { }
			}
			
			
			function local:Set-Icon
			{
				param (
					[Parameter(Position = 0, Mandatory = $True)]
					[String]$ProgId,
					[Parameter(Position = 1, Mandatory = $True)]
					[String]$Icon
				)
				
				try
				{
					$keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\DefaultIcon"
					[Microsoft.Win32.Registry]::SetValue($keyPath, "", $Icon)
					Write-Verbose "Write Reg Icon OK"
					Write-Verbose "Reg Icon: $keyPath"
				}
				catch
				{
					Write-Verbose "Write Reg Icon Fail"
				}
			}
			
			
			function local:Write-ExtensionKeys
			{
				param (
					[Parameter(Position = 0, Mandatory = $True)]
					[String]$ProgId,
					[Parameter(Position = 1, Mandatory = $True)]
					[String]$Extension,
					[Parameter(Position = 2, Mandatory = $True)]
					[String]$ProgHash
				)
				
				
				function local:Remove-UserChoiceKey
				{
					param (
						[Parameter(Position = 0, Mandatory = $True)]
						[String]$Key
					)
					
					$code = @"
      using System;
      using System.Runtime.InteropServices;
      using Microsoft.Win32;
      
      namespace Registry {
        public class Utils {
          [DllImport("advapi32.dll", SetLastError = true)]
          private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
      
          [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
          private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);
  
          public static void DeleteKey(string key) {
            UIntPtr hKey = UIntPtr.Zero;
            RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
            RegDeleteKey((UIntPtr)0x80000001u, key);
          }
        }
      }
"@
					
					try
					{
						Add-Type -TypeDefinition $code
					}
					catch { }
					
					try
					{
						[Registry.Utils]::DeleteKey($Key)
					}
					catch { }
				}
				
				
				try
				{
					$keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
					Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
					Remove-UserChoiceKey $keyPath
				}
				catch
				{
					Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
				}
				
				
				try
				{
					$keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
					[Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
					[Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
					Write-Verbose "Write Reg Extension UserChoice OK"
				}
				catch
				{
					throw "Write Reg Extension UserChoice FAIL"
				}
			}
			
			
			function local:Write-ProtocolKeys
			{
				param (
					[Parameter(Position = 0, Mandatory = $True)]
					[String]$ProgId,
					[Parameter(Position = 1, Mandatory = $True)]
					[String]$Protocol,
					[Parameter(Position = 2, Mandatory = $True)]
					[String]$ProgHash
				)
				
				
				try
				{
					$keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
					Write-Verbose "Remove Protocol UserChoice Key If Exist: $keyPath"
					Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
					
				}
				catch
				{
					Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
				}
				
				
				try
				{
					$keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
					[Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
					[Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
					Write-Verbose "Write Reg Protocol UserChoice OK"
				}
				catch
				{
					throw "Write Reg Protocol UserChoice FAIL"
				}
				
			}
			
			
			function local:Get-UserExperience
			{
				[OutputType([string])]
				
				$userExperienceSearch = "User Choice set via Windows User Experience"
				$user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
				$fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
				$binaryReader = New-Object System.IO.BinaryReader($fileStream)
				[Byte[]]$bytesData = $binaryReader.ReadBytes(5mb)
				$fileStream.Close()
				$dataString = [Text.Encoding]::Unicode.GetString($bytesData)
				$position1 = $dataString.IndexOf($userExperienceSearch)
				$position2 = $dataString.IndexOf("}", $position1)
				
				Write-Output $dataString.Substring($position1, $position2 - $position1 + 1)
			}
			
			
			function local:Get-UserSid
			{
				[OutputType([string])]
				$userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
				Write-Output $userSid
			}
			
			
			function local:Get-HexDateTime
			{
				[OutputType([string])]
				
				$now = [DateTime]::Now
				$dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
				$fileTime = $dateTime.ToFileTime()
				$hi = ($fileTime -shr 32)
				$low = ($fileTime -band 0xFFFFFFFFL)
				$dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
				Write-Output $dateTimeHex
			}
			
			function Get-Hash
			{
				[CmdletBinding()]
				param (
					[Parameter(Position = 0, Mandatory = $True)]
					[string]$BaseInfo
				)
				
				
				function local:Get-ShiftRight
				{
					[CmdletBinding()]
					param (
						[Parameter(Position = 0, Mandatory = $true)]
						[long]$iValue,
						[Parameter(Position = 1, Mandatory = $true)]
						[int]$iCount
					)
					
					if ($iValue -band 0x80000000)
					{
						Write-Output (($iValue -shr $iCount) -bxor 0xFFFF0000)
					}
					else
					{
						Write-Output  ($iValue -shr $iCount)
					}
				}
				
				
				function local:Get-Long
				{
					[CmdletBinding()]
					param (
						[Parameter(Position = 0, Mandatory = $true)]
						[byte[]]$Bytes,
						[Parameter(Position = 1)]
						[int]$Index = 0
					)
					
					Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
				}
				
				
				function local:Convert-Int32
				{
					param (
						[Parameter(Position = 0, Mandatory = $true)]
						$Value
					)
					
					[byte[]]$bytes = [BitConverter]::GetBytes($Value)
					return [BitConverter]::ToInt32($bytes, 0)
				}
				
				[Byte[]]$bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo)
				$bytesBaseInfo += 0x00, 0x00
				
				$MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
				[Byte[]]$bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
				
				$lengthBase = ($baseInfo.Length * 2) + 2
				$length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
				$base64Hash = ""
				
				if ($length -gt 1)
				{
					
					$map = @{
						PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
						R0    = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
					}
					
					$map.CACHE = 0
					$map.OUTHASH1 = 0
					$map.PDATA = 0
					$map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
					$map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
					$map.INDEX = Get-ShiftRight ($length - 2) 1
					$map.COUNTER = $map.INDEX + 1
					
					while ($map.COUNTER)
					{
						$map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
						$map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
						$map.PDATA = $map.PDATA + 8
						$map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
						$map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
						$map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16)))
						$map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
						$map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
						$map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
						$map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
						$map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
						$map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
						$map.CACHE = ([long]$map.OUTHASH2)
						$map.COUNTER = $map.COUNTER - 1
					}
					
					[Byte[]]$outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
					[byte[]]$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
					$buffer.CopyTo($outHash, 0)
					$buffer = [BitConverter]::GetBytes($map.OUTHASH2)
					$buffer.CopyTo($outHash, 4)
					
					$map = @{
						PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
						R0    = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
					}
					
					$map.CACHE = 0
					$map.OUTHASH1 = 0
					$map.PDATA = 0
					$map.MD51 = ((Get-Long $bytesMD5) -bor 1)
					$map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
					$map.INDEX = Get-ShiftRight ($length - 2) 1
					$map.COUNTER = $map.INDEX + 1
					
					while ($map.COUNTER)
					{
						$map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
						$map.PDATA = $map.PDATA + 8
						$map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
						$map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
						$map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
						$map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
						$map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
						$map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
						$map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
						$map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
						$map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
						$map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
						$map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3)
						$map.CACHE = ([long]$map.OUTHASH2)
						$map.COUNTER = $map.COUNTER - 1
					}
					
					$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
					$buffer.CopyTo($outHash, 8)
					$buffer = [BitConverter]::GetBytes($map.OUTHASH2)
					$buffer.CopyTo($outHash, 12)
					
					[Byte[]]$outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
					$hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
					$hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
					
					$buffer = [BitConverter]::GetBytes($hashValue1)
					$buffer.CopyTo($outHashBase, 0)
					$buffer = [BitConverter]::GetBytes($hashValue2)
					$buffer.CopyTo($outHashBase, 4)
					$base64Hash = [Convert]::ToBase64String($outHashBase)
				}
				
				Write-Output $base64Hash
			}
			
			Write-Verbose "Getting Hash For $ProgId   $Extension"
			
			$userSid = Get-UserSid
			$userExperience = Get-UserExperience
			$userDateTime = Get-HexDateTime
			Write-Debug "UserDateTime: $userDateTime"
			Write-Debug "UserSid: $userSid"
			Write-Debug "UserExperience: $userExperience"
			
			$baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
			Write-Verbose "baseInfo: $baseInfo"
			
			$progHash = Get-Hash $baseInfo
			Write-Verbose "Hash: $progHash"
			
			#Handle Extension Or Protocol
			if ($Extension.Contains("."))
			{
				Write-Verbose "Write Registry Extension: $Extension"
				Write-ExtensionKeys $ProgId $Extension $progHash
				
			}
			else
			{
				Write-Verbose "Write Registry Protocol: $Extension"
				Write-ProtocolKeys $ProgId $Extension $progHash
			}
			
			
			if ($Icon)
			{
				Write-Verbose  "Set Icon: $Icon"
				Set-Icon $ProgId $Icon
			}
			
			Update-RegistryChanges
			
		}
		
		function Set-PTA
		{
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[String]$ProgId,
				[Parameter(Mandatory = $true)]
				[String]$Protocol,
				[String]$Icon
			)
			
			Set-FTA -ProgId $ProgId -Protocol $Protocol -Icon $Icon
		}
		
		foreach ($default in $defaults)
		{
			Write-Output "$($default.command) $($default.program) $($default.extension)"
			Invoke-Expression -Command "$($default.command) $($default.program) $($default.extension)"
		}
	}
	try { Invoke-AsCurrentUser -ScriptBlock $default -CacheToDisk -ErrorAction Stop } <# Set Default app #>
	catch [Microsoft.PowerShell.Commands.WriteErrorException] { Invoke-Command -Command $default }
}

function Set-Shortcuts <# Add shortcuts on desktop #>
{
	[ScriptBlock]$scriptBlock = {
		$exeShortcuts = @(
			@{
				lnk = "Word.lnk"
				exe = "Winword.exe"
			} <# Word #>
			@{
				lnk = "Excel.lnk"
				exe = "Excel.exe"
			} <# Excel #>
			@{
				lnk = "PowerPoint.lnk"
				exe = "POWERPNT.exe"
			} <# PowerPoint #>
			@{
				lnk = "Outlook.lnk"
				exe = "Outlook.exe"
			} <# Outlook #>
			@{
				lnk = "Project.lnk"
				exe = "WINPROJ.exe"
			} <# Project #>
			@{
				lnk = "Visio.lnk"
				exe = "Visio.exe"
			} <# Visio #>
		)
		
		if (Test-Path "$env:OneDrive\Desktop") { $desktopDir = "$env:OneDrive\Desktop" }
		else { $desktopDir = "$env:USERPROFILE\Desktop" }
		
		[Switch]$found = $false
		$installTests = "$env:ProgramFiles\Microsoft Office\root\Office16", "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16"
		foreach ($installTest in $installTests) { if (Test-Path -Path $installTest) { [Switch]$found = $true; break } } <# Test for install #>
		
		if ($found)
		{
			foreach ($exeShortcut in $exeShortcuts)
			{
				$lnk = $exeShortcut.lnk
				$exe = $exeShortcut.exe
				$WshShell = New-Object -comObject WScript.Shell
				$Shortcut = $WshShell.CreateShortcut("$desktopDir\$lnk")
				$Shortcut.TargetPath = "$installTest\$exe"
				if (Test-Path "$installTest\$exe") { $Shortcut.Save() }
			}
		}
	}
	try { Invoke-AsCurrentUser -ScriptBlock $scriptBlock -CacheToDisk -ErrorAction Stop } <# Set Default app #>
	catch [Microsoft.PowerShell.Commands.WriteErrorException] { Invoke-Command -Command $scriptBlock }
}

function Uninstall-Windows10Apps
{
	param (
		[Parameter(Mandatory = $true)]
		[array]$Apps
	)
	foreach ($app in $apps)
	{
		# Remove the office apps for Windows 10
		if (Get-AppxPackage -Name $app -AllUsers)
		{ Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -Verbose:$false *>$null -ErrorAction Continue }
		if (Get-appxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app })
		{ Get-appxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } | Remove-AppxProvisionedPackage -Online -AllUsers -Verbose:$false *>$null -ErrorAction Continue }
	}
}

function Update-Office
{
	[ScriptBlock]$scriptBlock = {
		$installTests = "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe", "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
		foreach ($installTest in $installTests)
		{
			if (Test-Path -Path $installTest) { break }
		} <# Test for install #>
		
		if (Test-Path "$installTest") { Start-Process "$installTest" -ArgumentList "/update user updatepromptuser=false forceappshutdown=true displaylevel=false" }
	}
	try { Invoke-AsCurrentUser -ScriptBlock $scriptBlock -CacheToDisk -ErrorAction Stop } <# Set Default app #>
	catch [Microsoft.PowerShell.Commands.WriteErrorException] { Invoke-Command -Command $scriptBlock }
}

function Install-CustomModule
{
	param (
		[Parameter(Mandatory = $true)]
		[Array]$modules
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

# Run Commands
Install-CustomModule -Modules "RunAsUser"
Uninstall-Windows10Apps -Apps "*Microsoft.windowscommunicationsapps*", "*OfficeHub*"
Install-Program @InstallParameters
Set-Shortcuts
Set-Default
Update-Office
