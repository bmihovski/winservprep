#1. Create an infrastructure with two Windows Server machines:
#    ◦ M1 with two network adapters – one connected to the external LAN and one connected to an internal (private) network
#    ◦ M2 with one network adapter connected to the internal (private) network
# git push --porcelain
Get-NetAdapter
Rename-NetAdapter -Name ethernet -NewName Internet
Rename-NetAdapter -Name 'ethernet 2' -NewName Internal
Rename-Computer -NewName M1
Restart-Computer
# M2
Rename-NetAdapter -Name ethernet -NewName internal
Rename-Computer -NewName M2
Restart-Computer
#2. Install and configure DHCP role on M1 with binding to the internal network adapter and scope of 192.168.100.0/24
New-NetIPAddress -IPAddress 192.168.100.1 -PrefixLength 24 -InterfaceAlias internal
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Add-DhcpServerSecurityGroup -computername M1
Restart-Service -Name DHCPServer
Get-DhcpServerv4Binding
Set-DhcpServerv4Binding -InterfaceAlias internal -BindingState $true
Add-DhcpServerv4Scope -Name 'DHCP Internal Network' -StartRange 192.168.100.100 -EndRange 192.168.100.150 -SubnetMask 255.255.255.0
Get-DhcpServerv4Binding
Set-DhcpServerv4OptionValue -OptionId 3 -Value 192.168.100.1
Set-DhcpServerv4OptionValue -OptionId 6 -Value 192.168.100.1 -Force
#3. Setup an AD DS on M1 with domain name exam.text
Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "exam.text" `
-DomainNetbiosName "EXAM" `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
Add-DhcpServerInDC
#4. Join M2 to the domain
New-ADComputer -Name M2
#M2
Add-Computer -DomainName exam.text -DomainCredential Administrator
Get-ADComputer m2
#5. Create the following hierarchy of AD objects:
#        ◦ OU: IT
#            ▪ USR: Ivan Petkov (i.petkov)
#            ▪ USR: Tosho Tishev (t.tishev)
#        ◦ OU: Sales
#            ▪ USR: Petya Staikova (p.staikova)
#            ▪ USR: Mira Koleva (m.koleva)
#        ◦ GS: GS IT with members users in IT OU
#        ◦ GS: GS Sales with members users in Sales OU
# windows core allow esc to change the user only if basic session is used
New-ADOrganizationalUnit -Name IT
New-ADOrganizationalUnit -Name Sales
New-ADGroup -Name 'GS IT' -Description 'members users in IT OU' -GroupCategory Security -GroupScope DomainLocal -SamAccountName 'GS IT' `
-Path 'ou=it,dc=exam,dc=text'
New-ADGroup -Name 'GS Sales' -Description 'members users in Sales OU' -GroupCategory Security -GroupScope DomainLocal -SamAccountName 'GS Sales' `
-Path 'ou=sales,dc=exam,dc=text'
New-ADUser -Name Ivan -SamAccountName i.petkov -GivenName Ivan -Surname Petkov `
-AccountPassword (ConvertTo-SecureString -AsPlainText Password1 -Force) `
-UserPrincipalName i.petkov@exam.text `
-Enabled $true
New-ADUser -Name Tosho -SamAccountName t.tishev -GivenName Tosho -Surname Tishev `
-AccountPassword (ConvertTo-SecureString -AsPlainText Password1 -Force) `
-UserPrincipalName t.tishev@exam.text `
-Enabled $true
New-ADUser -Name Petya -SamAccountName p.staikova -GivenName Petya -Surname Staikova `
-AccountPassword (ConvertTo-SecureString -AsPlainText Password1 -Force) `
-UserPrincipalName p.staikova@exam.text `
-Enabled $true
New-ADUser -Name Mira -SamAccountName m.koleva -GivenName Mira -Surname Koleva `
-AccountPassword (ConvertTo-SecureString -AsPlainText Password1 -Force) `
-UserPrincipalName m.koleva@exam.text `
-Enabled $true
Get-ADGroup -Identity 'GS IT'
Add-ADGroupMember -Identity 'GS IT' -Members i.petkov,t.tishev
Get-ADGroup -Identity 'gs sales'
Add-ADGroupMember -Identity 'gs sales' -Members p.staikova,m.koleva
#6. Create and apply a GPO that enables remote management and ping on all machines in the domain
# Go to Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM.
# Go to Computer Configuration > Policies > Preferences > Control Panel Settings. And right-click Services and choose New > Service.
# Choose Automatic (Delayed Start) as startup type, pick WinRM as the service name, set Start service as the action.
# Go to Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Windows Firewall\Domain Profile and set Windows Firewall: Protect all network connections to Enabled
# Go to Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Inbound Rules enable predefined rules Windows Remote Management WRM
# To reduce the exposure to this service we can remove the Private and only leave only Domain profile in place. Double-click the new rule we just created, go to Advanced tab and uncheck the Private option from the Profiles section.
# Add custom inbound rule protocol and ports icmpv4 and profile domain
# restart M2
#7. Format the second HDD of M1 with NTFS, label it DATA, and mount it as X:
get-disk
Initialize-Disk -Number 1 -PartitionStyle GPT 
New-Partition -DiskNumber 1 -DriveLetter X -UseMaximumSize 
Initialize-Volume -DriveLetter X -FileSystem NTFS -NewFileSystemLabel DATA
#8. On M1 create share \\M1\Shared for folder C:\Shared and set permissions Full Control to Everyone
Install-WindowsFeature -Name file-services
mkdir C:\Shared
New-SmbShare -Name Shared -Path C:\Shared -FullAccess Everyone
#9. Create and apply a GPO that maps the \\M1\Shared as Z:\ only for users in Sales OU
# Add new policy object MountSales and change targeting from common and tick reconnect
# Link rule to Sales OU
# M2 with sales user
Get-SmbMapping Z
#10. Create scheduled daily (every day at 21:30) backup of C:\Shared to X:\Backup
Install-WindowsFeature -name Windows-Server-Backup -IncludeManagementTools
$policy = New-WBPolicy
$fileSpec = New-WBFileSpec -FileSpec C:\Shared
Add-WBFileSpec -Policy $policy -FileSpec $fileSpec
Get-WBDisk
$backupLocation = New-WBBackupTarget -VolumePath X:
Add-WBBackupTarget -Policy $policy -Target $backupLocation
Set-WBSchedule -Policy $Policy "09:30 PM"
Set-WBVssBackupOptions -Policy $policy -VssCopyBackup
Set-WBPolicy -Policy $policy
Get-WBSchedule -Policy $policy
# Note it is not possible to backup on folder only to value or network path the requirement is wrong
#11. Create a PowerShell script monitor.ps1 in C:\Scripts to count the files in C:\Shared and save the result
# in C:\Temp in a text file with a name monitor-files.log and schedule it to run every 2 minutes
mkdir c:\Scripts
mkdir c:\Temp
echo 'test' > C:\Shared\test.txt
"Get-ChildItem C:\Shared -Recurse -File | Measure-Object | %{$_.Count} | Out-File -FilePath 'C:\Temp\monitor-files.log' -Append;"
cp monitor.ps1 C:\Scripts\monitor.ps1
cat C:\Scripts\monitor.ps1
$action = New-ScheduledTaskAction -Execute C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Argument C:\Scripts\monitor.ps1
$interval = (New-TimeSpan -Minutes 2)
$dt= ([DateTime]::Now)
$duration = $dt.AddYears(25) -$dt;
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $interval -RepetitionDuration $duration 
$task = New-ScheduledTask -Action $action -Trigger $trigger
Register-ScheduledTask -TaskName CPULOAD -InputObject $task
echo 'test' > C:\Shared\test2.txt
cat C:\Temp\monitor-files.log
echo 'test' > C:\Shared\test3.txt