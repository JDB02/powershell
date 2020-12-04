$OutputFile = "C:\temp\$env:computername $(get-date -format 'dd-MMM-yyyy_HH:mm:ss' | ForEach-Object {$_ -replace ':', '_'}).csv"

" "
" "
" "
" "

echo "============================================================================================================"
echo "============================================================================================================"
echo "=====================================Powershell Incident Response==========================================="
echo "=======================================Press CTRL-C to terminate============================================"
echo "============================================================================================================"
echo "============================================================================================================"



echo "Powershell IR Script" | out-file –Append $OutputFile

Set-ExecutionPolicy Unrestricted -force

Get-Date | out-file –Append $OutputFile

echo "Computer Name:" | out-file –Append $OutputFile
$env:computername | out-file –Append $OutputFile

echo "===================================" | out-file –Append $OutputFile
echo "===================================" | out-file –Append $OutputFile
echo "===================================" | out-file –Append $OutputFile

Echo "Get-Execution Policy" | out-file –Append $OutputFile
Get-ExecutionPolicy -List | out-file –Append $OutputFile

" " | out-file –Append $OutputFile
" " | out-file –Append $OutputFile

Echo "Computer Name" | out-file –Append $OutputFile
$env:computername | out-file –Append $OutputFile

" " | out-file –Append $OutputFile
" " | out-file –Append $OutputFile

Echo "$PSVersionTable.PSVersion" | out-file –Append $OutputFile
$PSVersionTable.PSVersion | out-file –Append $OutputFile

" " | out-file –Append $OutputFile
" " | out-file –Append $OutputFile

Echo "Get-PSDrive" | out-file –Append $OutputFile
Get-PSDrive | out-file –Append $OutputFile

Echo "Get-Volume" | out-file –Append $OutputFile
Get-Volume | out-file –Append $OutputFile

Echo "Get-Host" | out-file –Append $OutputFile
Get-Host | out-file –Append $OutputFile

Echo "Get-Acl" | out-file –Append $OutputFile
Get-Acl | out-file –Append $OutputFile


Echo "Get-Computerinfo" | out-file –Append $OutputFile
Get-computerinfo | out-file –Append $OutputFile

" " | out-file –Append $OutputFile
" " | out-file –Append $OutputFile

Echo systeminfo | out-file –Append $OutputFile
" " | out-file –Append $OutputFile
Systeminfo | out-file –Append $OutputFile

" " | out-file –Append $OutputFile
" " | out-file –Append $OutputFile


Echo "Get-CimInstance –ClassName Win32_StartupCommand | Select-Object –Property Command, Description, user, Location" | out-file –Append $OutputFile
Get-CimInstance –ClassName Win32_StartupCommand | Select-Object –Property Command, Description, user, Location | out-file –Append $OutputFile

Echo "Get-LocalUser" | out-file –Append $OutputFile
Get-LocalUser| out-file –Append $OutputFile

Echo "Get-LocalUser | where Enabled –eq $True" | out-file –Append $OutputFile
Get-LocalUser | where Enabled –eq $True | out-file –Append $OutputFile

Echo "Get-LocalGroup" | out-file –Append $OutputFile
Get-LocalGroup | out-file –Append $OutputFile

Echo "Get-LocalGroup Member Administrators" | out-file –Append $OutputFile
Get-LocalGroup Member Administrators | out-file –Append $OutputFile

Echo "Get-ADUser –Filter ‘Name –Like "*"’ | where Enabled –eq $True" | out-file –Append $OutputFile
Get-ADUser –Filter ‘Name –Like "*"’ | where Enabled –eq $True | out-file –Append $OutputFile

Echo "Get-ADGroupMember Administrators| where objectClass –eq ‘user’" | out-file –Append $OutputFile
Get-ADGroupMember Administrators| where objectClass –eq ‘user’ | out-file –Append $OutputFile

Echo "Get-ADComputer –Filter "Name –Like ‘*’" –Properties * | where Enabled –eq $True | Select-Object name, OperatingSystem, Enabled" | out-file –Append $OutputFile
Get-ADComputer –Filter "Name –Like ‘*’" –Properties * | where Enabled –eq $True | Select-Object name, OperatingSystem, Enabled | out-file –Append $OutputFile

Echo "Get-CimInstance –ClassName win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage" | out-file –Append $OutputFile
Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | out-file –Append $OutputFile

Echo "Get-itemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\uninstall*" | where displayname –Like "*wireshark*" |Select-Object DisplayName, DisplayVersion, InstallDate, Publisher" | out-file –Append $OutputFile
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where DisplayName -Like "*wire*" |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | out-file –Append $OutputFile

Echo "Get-itemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\uninstall*" | where DisplayName -Like "*NVIDIA*" |Select-Object DisplayName, DisplayVersion, InstallDate, Publisher" | out-file –Append $OutputFile
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where DisplayName -Like "*NVIDIA*" |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | out-file –Append $OutputFile

Echo "Running Services" | out-file –Append $OutputFile
Get-Service | where-object {$_.Status -eq "running"} | Format-table -Autosize | out-file –Append $OutputFile

Echo "Stopped Services" | out-file –Append $OutputFile
Get-Service | where-object {$_.Status -eq "stopped"} | Format-table -Autosize |  out-file –Append $OutputFile

Echo "Services that have dependant services" | out-file –Append $OutputFile
Get-Service | Where-Object {$_.DependentServices} | Format-List -Property Name, DependentServices, @{Label="NoOfDependentServices"; Expression={$_.dependentservices.count}}| out-file –Append $OutputFile

Echo "show recent USB activity" | out-file -Append $OutputFile
Get-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName | out-file -Append $OutputFile

Echo "Event Log Warning Messages" | out-file -Append $OutputFile
Get-WinEvent -LogName System -MaxEvents 100 | where LevelDisplayName -eq warning | Format-table -Autosize | out-file -Append $OutputFile

Echo "Event Log Error Messages" | out-file -Append $OutputFile
Get-WinEvent -LogName System -MaxEvents 100 | where LevelDisplayName -eq error| Format-table -Autosize | out-file -Append $OutputFile

Echo " Get-DnsClientCache | Select-Object –Property Entry " | out-file -Append $OutputFile
Get-DnsClientCache | Select-Object -Property Entry | out-file -Append $OutputFile

Echo "Established TCP Connections and their associated Owning Processes" | out-file -Append $OutputFile
Get-NetTCPConnection| Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{n="UserName";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}}| Where {$_.State -eq"Established"} |FT -autosize -Force | out-file -Append $OutputFile

Echo "Listening TCP Connections and their associated Owning Processes" | out-file -Append $OutputFile
Get-NetTCPConnection| Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{n="UserName";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}}| Where {$_.State -eq"Listen"} |FT -autosize -Force | out-file -Append $OutputFile

Echo "Bound, TimeWait, & CloseWait TCP Connections and their associated Owning Processes" | out-file -Append $OutputFile
Get-NetTCPConnection| Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{n="UserName";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}} | Where {$_.State -eq"Bound" -Or $_.State -eq"TimeWait" -Or $_.State -eq"CloseWait" } |FT -autosize -Force  | out-file -Append $OutputFile


"===============FILE HASHES==============="

$DriverHASHOutputFile = "C:\temp\$env:computername $(get-date –format "dd-MMM-yyyy_HH:mm:ss" | ForEach-Object { $_ -replace ":", "_" })_System32_Driver_Hashes.csv"

$env:computername | out-file –Append $DriverHASHOutputFile



Echo "System32 Driver Hashes" | out-file –Append $DriverHASHOutputFile
Get-ChildItem C:\windows\system32\drivers\ -Recurse | Get-FileHash | Select-Object -Property hash, Path | Format-Table –HideTableHeaders –Autosize | out-file –Append $DriverHASHOutputFile

$sysWOW64HASHOutputFile = "C:\temp\$env:computername $(get-date –format "dd-MMM-yyyy_HH:mm:ss" | ForEach-Object { $_ -replace ":", "_" })_SysWOW64_Hashes.csv"

$env:computername | out-file –Append $sysWOW64HASHOutputFile



Echo "SYSWOW64 Hashes" | out-file –Append $sysWOW64HASHOutputFile
Get-ChildItem C:\windows\SysWOW64\ -Recurse | Get-FileHash | Select-Object -Property hash, Path | Format-Table –HideTableHeaders –Autosize | out-file –Append $sysWOW64HASHOutputFile
