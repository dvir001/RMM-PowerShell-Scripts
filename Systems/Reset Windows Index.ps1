function Reset-Search
{
	[ScriptBlock]$scriptBlock = {
		function T-R
		{
			[CmdletBinding()]
			Param (
				[String]$n
			)
			
			$o = Get-Item -LiteralPath $n -ErrorAction SilentlyContinue
			return ($o -ne $null)
		}
		
		function R-R
		{
			[CmdletBinding()]
			Param (
				[String]$l
			)
			
			$m = T-R $l
			if ($m)
			{
				Remove-Item -Path $l -Recurse -ErrorAction SilentlyContinue
			}
		}
		
		function S-D
		{
			R-R "HKLM:\SOFTWARE\Microsoft\Cortana\Testability"
			R-R "HKLM:\SOFTWARE\Microsoft\Search\Testability"
		}
		
		function K-P
		{
			[CmdletBinding()]
			Param (
				[String]$g
			)
			
			$h = Get-Process $g -ErrorAction SilentlyContinue
			
			$i = $(get-date).AddSeconds(2)
			$k = $(get-date)
			
			while ((($i - $k) -gt 0) -and $h)
			{
				$k = $(get-date)
				
				$h = Get-Process $g -ErrorAction SilentlyContinue
				if ($h)
				{
					$h.CloseMainWindow() | Out-Null
					Stop-Process -Id $h.Id -Force
				}
				
				$h = Get-Process $g -ErrorAction SilentlyContinue
			}
		}
		
		function D-FF
		{
			[CmdletBinding()]
			Param (
				[string[]]$e
			)
			
			foreach ($f in $e)
			{
				if (Test-Path -Path $f)
				{
					Remove-Item -Recurse -Force $f -ErrorAction SilentlyContinue
				}
			}
		}
		
		function D-W
		{
			
			$d = @("$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\AppCache",
				"$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\INetCache",
				"$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\INetCookies",
				"$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\INetHistory",
				"$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\AppCache",
				"$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\INetCache",
				"$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\INetCookies",
				"$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\INetHistory",
				"$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\AppCache",
				"$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\INetCache",
				"$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\INetCookies",
				"$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\INetHistory",
				"$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\AppCache",
				"$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCache",
				"$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCookies",
				"$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetHistory")
			
			D-FF $d
		}
		
		function R-L
		{
			[CmdletBinding()]
			Param (
				[String]$c
			)
			
			K-P $c 2>&1 | out-null
			D-W # 2>&1 | out-null
			K-P $c 2>&1 | out-null
			
			Start-Sleep -s 5
		}
		
		$a = "searchui"
		$b = "$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy"
		if (Test-Path -Path $b)
		{
			$a = "searchapp"
		}
		
		
		Write-Output "Resetting Windows Search Box"
		S-D 2>&1 | out-null
		R-L $a
		
		Write-Output "Done..."
	}
	
	try { Invoke-AsCurrentUser -ScriptBlock $scriptBlock -CacheToDisk -ErrorAction Stop }
	catch [Microsoft.PowerShell.Commands.WriteErrorException] { Invoke-Command -Command $scriptBlock }
}

function Reset-Index
{
	$ErrorActionPreference = 'Stop'
	
	Function Feedback
	{
		Param (
			[Parameter(Mandatory = $true,
					   Position = 0)]
			[string]$Message,
			[Parameter(Mandatory = $false,
					   Position = 1)]
			$Exception,
			[switch]$Oops
		)
		
		# This function provides feedback in the console on errors or progress, and aborts if error has occured.
		If (!$Exception -and !$Oops) { Write-Output $Message }
		
		# If an error occured report it, and exit the script with ErrorLevel 1
		else
		{
			# Write content of feedback string but to the error stream
			$Host.UI.WriteErrorLine($Message)
			
			# Display error details
			If ($Exception) { $Host.UI.WriteErrorLine("Exception detail:`n$Exception") }
			
			# Exit errorlevel 1
			break
		}
	}
	
	# Reconfigure Windows Search Service so that it will not restart straight away. Then stop the service.
	try
	{
		Set-Service -Name 'wsearch' -StartupType Disabled
		Stop-Service -Name 'wsearch' -Force
	}
	catch { Feedback -Message 'There was a problem reconfiguring and stopping the Windows Search Sevice.' -Exception $_ }
	
	# Delete the index file
	try { Remove-Item -Path "$([System.Environment]::ExpandEnvironmentVariables("%programdata%\microsoft\search\data\applications\windows\Windows.edb"))" -Force }
	catch
	{
		# If it fails, try to restart the service and inform the user
		try { Set-Service -Name 'wsearch' -StartupType Automatic }
		catch { Feedback -Message 'The Windows Search Index file could not be deleted. The Search service could not be set to start Automtically and restarted. Please check the machine to ensure the Search Service is configured as it should be again.' -Exception $_ }
		Feedback -Message 'The Windows Search Index file could not be deleted. The service has been set back to Automatic start and will start again in 2 minutes.' -Exception $_
	}
	
	# Set the Windows Search Service startup type back to Automatic.
	try { Set-Service -Name 'wsearch' -StartupType Automatic }
	catch { Feedback -Message 'The Windows Search Index file has been deleted but the Windows Search service could not be set to start automtically and restarted. Please check the machine to ensure the Search Service is configured as it should be again.' -Exception $_ }
	
	Feedback -Message "The Windows Search index file has been deleted. The service has been set back to Automtically start and should start in 2 minutes."
}

function Remove-OnlineSearch
{
	$searchkey = $null
	try
	{
		$searchkey = Get-Item -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -ErrorAction Stop
	}
	catch
	{ Write-Output "Remove-OnlineSearch: The Search registry key does not exist, so this user session is probably not running on Windows 10" }
	
	$valueexists = $false
	if ($searchkey -ne $null)
	{
		try
		{
			$bingvalue = Get-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -ErrorAction Stop
			if ($bingvalue.BingSearchEnabled -eq 0)
			{
				Write-Output "Remove-OnlineSearch: No change performed. BingSearchEnabled = 0"
			}
			else
			{
				Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -value '0' -Force -ErrorAction Stop
				if ($?) { Write-Output "Remove-OnlineSearch: BingSearchEnabled value set to 0" }
				else { Write-Output "Remove-OnlineSearch: Error setting registry value" }
			}
		}
		catch
		{
			New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -PropertyType DWORD
			if ($?) { Write-Output "Remove-OnlineSearch: BingSearchEnabled value created, value set to 0" }
			else { Write-Output "Remove-OnlineSearch: Error creating registry value" }
		}
	}
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
Reset-Search
Reset-Index
Remove-OnlineSearch
