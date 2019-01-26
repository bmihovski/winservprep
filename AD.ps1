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
