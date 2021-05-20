if(test-path "C:\ProgramData\chocolatey\choco.exe") { }
else { Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) }

# Install apps:
C:\ProgramData\chocolatey\choco.exe install microsoft-teams.install -y --acceptlicense

