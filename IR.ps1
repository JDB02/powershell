$OutFile = “C:\temp\$env:computername $(get-date –format “dd-MMM-yyyy_HH:mm:ss” | ForEach-Object { $_ -replace “:”, “_”}).csv”
 
echo “Powershell IR Script” | out-file –Append $OutputFile
echo “ Updated 11/20/2020” | out-file –Append $OutputFile
 
 
Get-Date | out-file –Append $OutputFile
 
echo “Computer Name:” | out-file –Append $OutputFile
$env:computername | out-file –Append $OutputFile
 
echo “ ===================================” | out-file –Append $OutputFile
echo “ ===================================” | out-file –Append $OutputFile
echo “ ===================================” | out-file –Append $OutputFile
 
Echo “Get-Execution Policy” | out-file –Append $OutputFile
Get-ExecutionPolicy | out-file –Append $OutputFile
 
“ “ | out-file –Append $OutputFile
“ “ | out-file –Append $OutputFile
 
Echo “Computer Name” | out-file –Append $OutputFile
$env:computername” | out-file –Append $OutputFile
 
“ “ | out-file –Append $OutputFile
“ “ | out-file –Append $OutputFile
 
Echo “$PSVersionTable.PSVersion” | out-file –Append $OutputFile
$PSVersionTable.PSVersion | out-file –Append $OutputFile
 
“ “ | out-file –Append $OutputFile
“ “ | out-file –Append $OutputFile
 
Echo “Get-PSDrive” | out-file –Append $OutputFile
Get-PSDrive | out-file –Append $OutputFile
 
Echo “Get-Volume” | out-file –Append $OutputFile
Get-Volume | out-file –Append $OutputFile
 
Echo “Get-Host” | out-file –Append $OutputFile
Get-Host | out-file –Append $OutputFile
 
Echo “Get-Acl” | out-file –Append $OutputFile
Get-Acl | out-file –Append $OutputFile
 
 
Echo “Get-Computerinfo” | out-file –Append $OutputFile
Get-computerinfo| out-file –Append $OutputFile
 
“ “ | out-file –Append $OutputFile
“ “ | out-file –Append $OutputFile
 
Echo systeminfo | out-file –Append $OutputFile
“ “ | out-file –Append $OutputFile
Systeminfo | out-file –Append $OutputFile
 
“ “ | out-file –Append $OutputFile
“ “ | out-file –Append $OutputFile
 
 
Echo “Get-CimInstance –ClassName Win32_StartupCommand | Select-Object –Property Command, Description, user, Location” | out-file –Append $OutputFile
Get-CimInstance –ClassName Win32_StartupCommand | Select-Object –Property Command, Description, user, Location | out-file –Append $OutputFile
 
Echo “Get-LocalUser” | out-file –Append $OutputFile
Get-LocalUser| out-file –Append $OutputFile
 
Echo “Get-LocalUser | where Enabled –eq $True” | out-file –Append $OutputFile
Get-LocalUser| where Enabled –eq $True | out-file –Append $OutputFile
 
Echo “Get-LocalGroup” | out-file –Append $OutputFile
Get-LocalGroup| out-file –Append $OutputFile
 
Echo “Get-LocalGroup Member Administrators” | out-file –Append $OutputFile
Get-LocalGroup Member Administrators| out-file –Append $OutputFile
 
Echo “Get-ADUser –Filter ‘Name –Like “*”’ | where Enabled –eq $True” | out-file –Append $OutputFile
Get-ADUser –Filter ‘Name –Like “*”’ | where Enabled –eq $True | out-file –Append $OutputFile
 
Echo “Get-ADGroupMember Administrators| where objectClass –eq ‘user’” | out-file –Append $OutputFile
Get-ADGroupMember Administrators| where objectClass –eq ‘user’ | out-file –Append $OutputFile
Echo “Get-ADComputer –Filter “Name –Like ‘*’” –Properties * | where Enabled –eq $True | Select-Object name, OperatingSystem, Enabled” | out-file –Append $OutputFile
Get- Get-ADComputer –Filter “Name –Like ‘*’” –Properties * | where Enabled –eq $True | Select-Object name, OperatingSystem, Enabled | out-file –Append $OutputFile
 
Echo “Get-CimInstance –ClassName win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource PackageName, LocalPackage” | out-file –Append $OutputFile
Get-CimInstance –ClassName win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource PackageName, LocalPackage | out-file –Append $OutputFile
 
Echo “Get-itemProperty “HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\uninstall*” | where displayname –Like “*wireshark*” |Select-Object DisplayName, DisplayVersion, InstallDate, Publisher” | out-file –Append $OutputFile
Get-itemProperty “HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\uninstall*” | where displayname –Like “*wireshark*” |Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | out-file –Append $OutputFile
 
Echo “Get-itemProperty “HKLM:\Software\ Microsoft\Windows\CurrentVersion\uninstall*” | where displayname –Like “*autopsy*” |Select-Object DisplayName, DisplayVersion, InstallDate, Publisher” | out-file –Append $OutputFile
Get-itemProperty “HKLM:\Software\Microsoft\Windows\CurrentVersion\uninstall*” | where displayname –Like “*autopsy *” |Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | out-file –Append $OutputFile
 
Echo “Running Services” | out-file –Append $OutputFile
Get-Service | where-object {$_.Status –eq “running”} |Format-Table-Autosize | out-file –Append $OutputFile
 
Echo “Stopped Services” | out-file –Append $OutputFile
Get-Service | where-object {$_.Status –eq “stopped”} | Format-Table-Autosize | out-file –Append $OutputFile
 
Echo “Services that have dependant services” | out-file –Append $OutputFile
Get-Service | where-object {$_.DependentServices} | Format-List –property name, DependentServices, @{Label=”NoOfSependentServices”; Expression={$_.dependentservices.count}} | out-file –Append $OutputFile
 
Echo “show recent USB activity” | out-file -Append $OutputFile
Get-ItemProperty -path HKLM:\SYSTEM]CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName | out-file -Append $OutputFile
 
 
Echo “Event Log Warning or Error Messages” | out-file -Append $OutputFile
Get-EventLog –LogName system –Newest 100 | Select-Object –Propert TimeGenerated, Source, EntryType, Message | where {$_.EntryType –eq “error”} | out-file -Append $OutputFile
 
Echo “ Get-DnsClientCache | Select-Object –Property Entry “ | out-file -Append $OutputFile
Get-DnsClientCache | Select-Object –Property Entry | out-file -Append $OutputFile
 
Echo “TCP Connections and their associated Owning Processes” | out-file -Append $OutputFile
Get-NetTCPConnection –State Establish | Format-Table –Autosize | out-file -Append $OutputFile
 
 
“===============FILE HASHES===============”
 
$DriverHASHOutputFile = “C:\temp\$env:computername $(get-date –format “dd-MMM-yyyy_HH:mm:ss” | ForEach-Object { $_ -replace “:”, “_” })_System32_Driver_Hashes.csv”
 
$env:computername | out-file –Append $DriverHASHOutputFile
Echo “===============SYSTEM32 DRIVER HASHES===============” | out-file –Append $DriverHASHOutputFile
 
 
Echo “System32 Driver Hashes” | out-file –Append $DriverHASHOutputFile
Get-ChildItem C:\windows\system32\drivers\ -Recurse |Get-FileHash | Select-Object –Property hash, Path | Format-Table –HideTableHeaders – Autosize | out-file –Append $DriverHASHOutputFile
 
$sysWOW64HASHOutputFile = “C:\temp\$env:computername $(get-date –format “dd-MMM-yyyy_HH:mm:ss” | ForEach-Object { $_ -replace “:”, “_” })_SysWOW64_Hashes.csv”
 
$env:computername | out-file –Append $sysWOW64HASHOutputFile
Echo “===============SYSWOW64 HASHES===============” | out-file –Append $sysWOW64HASHOutputFile
 
 
Echo “SYSWOW64 Hashes” | out-file –Append $sysWOW64HASHOutputFile
Get-ChildItem C:\windows\SysWOW64\ -Recurse |Get-FileHash | Select-Object –Property hash, Path | Format-Table –HideTableHeaders – Autosize | out-file –Append $sysWOW64HASHOutputFile
