
$path = "C:\temp\"
If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}

$OutputFile = "$path\$env:computername $(get-date -format "dd-MM-yyyy_HH:mm:ss" | ForEach-Object { $_ -replace ":", "_" }).csv"

# Variables
$Counter = 0
$Tasks = "Get-computername","WindowsCurrentVersion","ExecutionPolicy","PowerShellVersion","Get-System","PSDrives","Volume","GetHost","ComputerInfo","StartupPrograms","LocalUser","LocalGroup","Administrators","ADusers","ADAdministrators","ADComputers","InstalledPrograms","InstalledPrograms2","RunningServices","StoppedServices","DependentServices","USBActivity","USBActivity2","EventLog","DNSCache","PortsandProcesses","hashSYSTEM32","hashSYSWOW64"
	echo "POWERSHELL IR SCRIPT" | out-file -Append $OutputFile
	Get-Date | out-file -Append $OutputFile

    Function Get-computername {
    echo "Computer name:"| out-file -Append $OutputFile
	$env:computername | out-file -Append $OutputFile
	" "
	" "
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "

}
	
    Function WindowsCurrentVersion {
	echo "Operating System Information" | out-file -Append $OutputFile
	Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\"  | Select-Object ProductName, ReleaseID, InstallDate | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function ExecutionPolicy {
	echo "Show the Execution Policy" | out-file -Append $OutputFile
	Get-ExecutionPolicy -List | out-file -Append $OutputFile
	" "
	" "
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function PowerShellVersion {
	echo "Powershell Version" | out-file -Append $OutputFile
	$PSVersionTable.PSVersion | out-file -Append $OutputFile
	" "
	" "
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}

	Function Get-System {
	" "
	echo systeminfo | out-file -Append $OutputFile
	" "
	systeminfo | out-file -Append $OutputFile
	" "
	" "
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function PSDrives {
	echo "Get-PSDrive"  | out-file -Append $OutputFile
	Get-PSDrive  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function Volume {
	echo "Get-Volume"  | out-file -Append $OutputFile
	Get-Volume  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function GetHost {
	echo "Get-Host"  | out-file -Append $OutputFile
	Get-Host  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function ComputerInfo {
	echo "Get-ComputerInfo"  | out-file -Append $OutputFile
	Get-ComputerInfo  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function StartupPrograms {
	echo "Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location"  | out-file -Append $OutputFile
	Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function LocalUser {
	echo "Get-LocalUser" | out-file -Append $OutputFile
	Get-LocalUser | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function LocalGroup {
	echo "Get-LocalGroup"  | out-file -Append $OutputFile
	Get-LocalGroup | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function Administrators {
	echo "Get-LocalGroupMember Administrators"  | out-file -Append $OutputFile
	Get-LocalGroupMember Administrators | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function ADusers {
	echo "Get-ADUser -Filter 'Name -Like "*"' | where Enabled -eq $True" | out-file -Append $OutputFile
	Get-ADUser -Filter 'Name -Like "*"' | where Enabled -eq $True | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function ADAdministrators {
	echo "Get-ADGroupMember Administrators | where objectClass -eq 'user'"  | out-file -Append $OutputFile
	Get-ADGroupMember Administrators | where objectClass -eq 'user'  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function ADComputers {
	echo "Get-ADComputer -Filter "Name -Like '*'" -Properties * | where Enabled -eq $True | Select-Object Name, OperatingSystem, Enabled" | out-file -Append $OutputFile
	Get-ADComputer -Filter "Name -Like '*'" -Properties * | where Enabled -eq $True | Select-Object Name, OperatingSystem, Enabled | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function InstalledPrograms {
	echo "Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher" | out-file -Append $OutputFile
	Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function InstalledPrograms2 {
	echo "Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher" | out-file -Append $OutputFile
	Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function RunningServices {
	echo "Running Services" | out-file -Append $OutputFile
	Get-Service | where-object {$_.Status -eq "running"} | Format-Table -Autosize | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "	
	}
	
	Function StoppedServices {
	echo "Stopped Services" | out-file -Append $OutputFile
	Get-Service | where-object {$_.Status -eq "stopped"} | Format-Table -Autosize | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function DependentServices {
	echo "Services that have dependent services" | out-file -Append $OutputFile
	Get-Service | where-object {$_.DependentServices} | Format-List -property name, DependentServices, @{Label="NoOfDependentServices"; Expression={$_.dependentservices.count}} | out-file -Append $OutputFile	
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function USBActivity {
	echo "Show Recent USB Activity" | out-file -Append $OutputFile
	Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function USBActivity2 {
	echo "Show Recent USB Activity" | out-file -Append $OutputFile
	Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*  | Select DeviceDesc,Service,Mfg | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function EventLog {
	echo "Event Log Warning or Error Messages" | out-file -Append $OutputFile
	Get-Eventlog -LogName system -Newest 25 | Select-Object -Property TimeGenderated, Source, EntryType, Message | where {$_.EntryType -eq "warning" -or $_.EntryType -eq "error"}  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function DNSCache {
	echo "Get-DNS Client Cache | Select-Object -Property Entry"  | out-file -Append $OutputFile
	Get-DnsClientCache | Select-Object -Property Entry  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}
	
	Function PortsandProcesses {
	echo "TCP Connections and their associated Owning Processes"  | out-file -Append $OutputFile
	Get-NetTCPConnection -State Established | Format-Table -Autosize  | out-file -Append $OutputFile
	" "
	" "	
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	echo "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	" "
	" "
	}


For($Tasks = 1; $Tasks -le 100;$Tasks++) {
Write-Progress -Activity "Collecting Data" -Status "$Tasks% Complete" -PercentComplete $Tasks
Start-Sleep -Milliseconds 300
}
