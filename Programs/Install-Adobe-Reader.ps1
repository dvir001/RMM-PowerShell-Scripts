# Inputs
$program = "adobereader"
if(test-path "C:\ProgramData\chocolatey\choco.exe") { }
else { Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) }

C:\ProgramData\chocolatey\choco.exe install $program -y --acceptlicense

# Set Adobe as Default app
$source = @"
using System;
using System.Runtime.InteropServices;

namespace murrayju.ProcessExtensions
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
            return true;
        }
    }
}


"@

$script = @'
function Get-FTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [String]
    $Extension
  )

  
  if ($Extension) {
    Write-Verbose "Get File Type Association for $Extension"
    
    $assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"-ErrorAction SilentlyContinue).ProgId
    Write-Output $assocFile
  }
  else {
    Write-Verbose "Get File Type Association List"

    $assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\* |
    ForEach-Object {
      $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
      if ($progId) {
        "$($_.PSChildName), $progId"
      }
    }
    Write-Output $assocList
  }
  
}

function Get-PTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [String]
    $Protocol
  )

  if ($Protocol) {
    Write-Verbose "Get Protocol Type Association for $Protocol"

    $assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"-ErrorAction SilentlyContinue).ProgId
    Write-Output $assocFile
  }
  else {
    Write-Verbose "Get Protocol Type Association List"

    $assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\* |
    ForEach-Object {
      $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
      if ($progId) {
        "$($_.PSChildName), $progId"
      }
    }
    Write-Output $assocList
  }
}

function Register-FTA {
  [CmdletBinding()]
  param (
    [Parameter( Position = 0, Mandatory = $true)]
    [ValidateScript( { Test-Path $_ })]
    [String]
    $ProgramPath,

    [Parameter( Position = 1, Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,
    
    [Parameter( Position = 2, Mandatory = $false)]
    [String]
    $ProgId,
    
    [Parameter( Position = 3, Mandatory = $false)]
    [String]
    $Icon
  )

  Write-Verbose "Register Application + Set Association"
  Write-Verbose "Application Path: $ProgramPath"
  if ($Extension.Contains(".")) {
    Write-Verbose "Extension: $Extension"
  }
  else {
    Write-Verbose "Protocol: $Extension"
  }
  
  if (!$ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
  }
  
  $progCommand = """$ProgramPath"" ""%1"""
  Write-Verbose "ApplicationId: $ProgId" 
  Write-Verbose "ApplicationCommand: $progCommand"
  
  try {
    $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$Extension\OpenWithProgids"
    [Microsoft.Win32.Registry]::SetValue( $keyPath, $ProgId, ([byte[]]@()), [Microsoft.Win32.RegistryValueKind]::None)
    $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\shell\open\command"
    [Microsoft.Win32.Registry]::SetValue($keyPath, "", $progCommand)
    Write-Verbose "Register ProgId and ProgId Command OK"
  }
  catch {
    throw "Register ProgId and ProgId Command FAIL"
  }
  
  Set-FTA -ProgId $ProgId -Extension $Extension -Icon $Icon
}


function Remove-FTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [Alias("ProgId")]
    [String]
    $ProgramPath,

    [Parameter(Mandatory = $true)]
    [String]
    $Extension
  )
  
  function local:Remove-UserChoiceKey {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $Key
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

    try {
      Add-Type -TypeDefinition $code
    }
    catch {}

    try {
      [Registry.Utils]::DeleteKey($Key)
    }
    catch {} 
  } 

  function local:Update-Registry {
    $code = @"
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
"@ 

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {} 
  }

  if (Test-Path -Path $ProgramPath) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
  }
  else {
    $ProgId = $ProgramPath
  }

  try {
    $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    Write-Verbose "Remove User UserChoice Key If Exist: $keyPath"
    Remove-UserChoiceKey $keyPath

    $keyPath = "HKCU:\SOFTWARE\Classes\$ProgId"
    Write-Verbose "Remove Key If Exist: $keyPath"
    Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
    
  }
  catch {
    Write-Verbose "Key No Exist: $keyPath"
  }

  try {
    $keyPath = "HKCU:\SOFTWARE\Classes\$Extension\OpenWithProgids"
    Write-Verbose "Remove Property If Exist: $keyPath Property $ProgId"
    Remove-ItemProperty -Path $keyPath -Name $ProgId  -ErrorAction Stop | Out-Null
    
  }
  catch {
    Write-Verbose "Property No Exist: $keyPath Property: $ProgId"
  } 

  Update-Registry
  Write-Output "Removed: $ProgId" 
}


function Set-FTA {

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,
      
    [String]
    $Icon
  )
  
  if (Test-Path -Path $ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
  }

  Write-Verbose "ProgId: $ProgId"
  Write-Verbose "Extension/Protocol: $Extension"


  function local:Update-RegistryChanges {
    $code = @"
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
"@ 

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {} 
  }
  

  function local:Set-Icon {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Icon
    )

    try {
      $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\DefaultIcon"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "", $Icon) 
      Write-Verbose "Write Reg Icon OK"
      Write-Verbose "Reg Icon: $keyPath"
    }
    catch {
      Write-Verbose "Write Reg Icon Fail"
    }
  }


  function local:Write-ExtensionKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )
    

    function local:Remove-UserChoiceKey {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Key
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
  
      try {
        Add-Type -TypeDefinition $code
      }
      catch {}

      try {
        [Registry.Utils]::DeleteKey($Key)
      }
      catch {} 
    } 

    
    try {
      $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
      Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
      Remove-UserChoiceKey $keyPath
    }
    catch {
      Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
    }
  

    try {
      $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
      [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
      Write-Verbose "Write Reg Extension UserChoice OK"
    }
    catch {
      throw "Write Reg Extension UserChoice FAIL"
    }
  }


  function local:Write-ProtocolKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Protocol,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )
      

    try {
      $keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
      Write-Verbose "Remove Protocol UserChoice Key If Exist: $keyPath"
      Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
    
    }
    catch {
      Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
    }
  

    try {
      $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
      [Microsoft.Win32.Registry]::SetValue( $keyPath, "Hash", $ProgHash)
      [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
      Write-Verbose "Write Reg Protocol UserChoice OK"
    }
    catch {
      throw "Write Reg Protocol UserChoice FAIL"
    }
    
  }

  
  function local:Get-UserExperience {
    [OutputType([string])]
      
    $userExperienceSearch = "User Choice set via Windows User Experience"
    $user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
    $fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $binaryReader = New-Object System.IO.BinaryReader($fileStream)
    [Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
    $fileStream.Close()
    $dataString = [Text.Encoding]::Unicode.GetString($bytesData)
    $position1 = $dataString.IndexOf($userExperienceSearch)
    $position2 = $dataString.IndexOf("}", $position1)

    Write-Output $dataString.Substring($position1, $position2 - $position1 + 1)
  }
  

  function local:Get-UserSid {
    [OutputType([string])]
    $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
    Write-Output $userSid
  }


  function local:Get-HexDateTime {
    [OutputType([string])]

    $now = [DateTime]::Now
    $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $dateTime.ToFileTime()
    $hi = ($fileTime -shr 32)
    $low = ($fileTime -band 0xFFFFFFFFL)
    $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
    Write-Output $dateTimeHex
  }
  
  function Get-Hash {
    [CmdletBinding()]
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [string]
      $BaseInfo
    )


    function local:Get-ShiftRight {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $iValue, 
            
        [Parameter( Position = 1, Mandatory = $true)]
        [int] $iCount 
      )
    
      if ($iValue -band 0x80000000) {
        Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
      }
      else {
        Write-Output  ($iValue -shr $iCount)
      }
    }
    

    function local:Get-Long {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [byte[]] $Bytes,
    
        [Parameter( Position = 1)]
        [int] $Index = 0
      )
    
      Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
    }
    

    function local:Convert-Int32 {
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        $Value
      )
    
      [byte[]] $bytes = [BitConverter]::GetBytes($Value)
      return [BitConverter]::ToInt32( $bytes, 0) 
    }

    [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
    $bytesBaseInfo += 0x00, 0x00  
    
    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
    
    $lengthBase = ($baseInfo.Length * 2) + 2 
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
    $base64Hash = ""

    if ($length -gt 1) {
    
      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }
    
      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1
    
      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
        $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
        $map.PDATA = $map.PDATA + 8
        $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
        $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
        $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
        $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
        $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
        $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
        $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }

      [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 0)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 4)
    
      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }
    
      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1

      while ($map.COUNTER) {
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
    
      [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
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
  if ($Extension.Contains(".")) {
    Write-Verbose "Write Registry Extension: $Extension"
    Write-ExtensionKeys $ProgId $Extension $progHash

  }
  else {
    Write-Verbose "Write Registry Protocol: $Extension"
    Write-ProtocolKeys $ProgId $Extension $progHash
  }

   
  if ($Icon) {
    Write-Verbose  "Set Icon: $Icon"
    Set-Icon $ProgId $Icon
  }

  Update-RegistryChanges 

}

function Set-PTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [String]
    $Protocol,
      
    [String]
    $Icon
  )

  Set-FTA -ProgId $ProgId -Protocol $Protocol -Icon $Icon
}

Set-FTA AcroExch.Document.DC .pdf

'@

$fileName = 'DefaultPDF.ps1'
$fileDir = 'C:\Temp'
$fileLocation = $fileDir + '\' + $fileName

If (!(test-path $fileDir)) { New-Item -ItemType Directory -Force -Path $fileDir }
If (test-path $fileLocation) { Remove-Item -Path $fileLocation -Force }
If (!(test-path $fileLocation)) { New-Item -Path $fileDir -Name $fileName -ItemType "file" -Value $script }

Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $source -Language CSharp

[murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser("$env:windir\System32\WindowsPowerShell\v1.0\Powershell.exe", " -ExecutionPolicy Bypass -WindowStyle Hidden -File $fileLocation")

