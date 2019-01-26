#1. Create an infrastructure with two Windows Server machines:
#    ◦ M1 with two network adapters – one connected to the external LAN and one connected to an internal (private) network
#    ◦ M2 with one network adapter connected to the internal (private) network
Get-NetAdapter
Rename-NetAdapter -Name ethernet -NewName Internet
Rename-NetAdapter -Name 'ethernet 2' -NewName Internal
Rename-Computer -NewName DC1
Restart-Computer
# CSERVER1
Rename-NetAdapter -Name ethernet -NewName internal
Rename-Computer -NewName CSERVER1
Restart-Computer