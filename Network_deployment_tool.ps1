<#
.SYNOPSIS
This script provides functionality to deploy a site to site VPN to a new or existing VNET.

.DESCRIPTION
Deploys a VNET, NSG and/or Site to Site VPN Connection.

.PARAMETER LocalNetIP

.PARAMETER NewVnet

.PARAMETER VMName

.PARAMETER ResourceGroupName

.PARAMETER LocalAddPrefix

.PARAMETER VNetName

.PARAMETER Location

.EXAMPLE
\.azdeploy.ps1 -VNETName vnet -LocalNetPip 120.2.3.1 -LocalAddPrefix 10.10.0.0/24 -ResourceGroupName ResGroup

.NOTES

.LINK
https://github.com/JonosGit/IaaSDeploymentTool
#>

param(
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$NewVnet = "True",
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$NSGEnabled = "False",
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$NSGName = "NSG",
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[ipaddress]
$LocalNetPip = "207.21.2.1",
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$LocalAddPrefix = "10.10.0.0/24",
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true,Position=2)]
[string]
$ResourceGroupName = 'ResGrp',
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$vNetResourceGroupName = $ResourceGroupName,
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$Location = "WestUs",
[Parameter(Mandatory=$False,ValueFromPipelinebyPropertyName=$true)]
[string]
$VNetName = "vnet"
)

Function VerifyProfile {
$ProfileFile = "c:\Temp\outlook.json"
$fileexist = Test-Path $ProfileFile
  if($fileexist)
  {Write-Host "Profile Found"
  Select-AzureRmProfile -Path $ProfileFile
  }
  else
  {
  Write-Host "Please enter your credentials"
  Add-AzureRmAccount
  }
}
Function ProvisionNet {
Write-Host "Network Preparation in Process.."
$subnet1 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.0.128/25 -Name perimeter
$subnet2 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.1.0/24 -Name web
$subnet3 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.2.0/24 -Name intake
$subnet4 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.3.0/24 -Name data
$subnet5 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.4.0/24 -Name monitoring
$subnet6 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.5.0/24 -Name analytics
$subnet7 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.6.0/24 -Name backup
$subnet8 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.7.0/24 -Name management
$subnet9 = New-AzureRmVirtualNetworkSubnetConfig -AddressPrefix 10.120.0.0/25 -Name GatewaySubnet
New-AzureRmVirtualNetwork -Location $Location -Name $VNetName -ResourceGroupName $vNetResourceGroupName -AddressPrefix '10.120.0.0/21' -Subnet $subnet9,$subnet1,$subnet2,$subnet3,$subnet4,$subnet5,$subnet6,$subnet7,$subnet8 –Confirm:$false -Force -WarningAction SilentlyContinue | Out-Null
Get-AzureRmVirtualNetwork -Name $VNetName -ResourceGroupName $vNetResourceGroupName | Get-AzureRmVirtualNetworkSubnetConfig -WarningAction SilentlyContinue | Out-Null
Write-Host "Network Preparation completed" -ForegroundColor White
}

# End of Provision VNET Function
Function CreateNSG {
if($NSGEnabled -eq "True")
{
Write-Host "Network Security Group Preparation in Process.."
$httprule = New-AzureRmNetworkSecurityRuleConfig -Name "FrontEnd_HTTP" -Description "HTTP Exception for Web frontends" -Protocol Tcp -SourcePortRange "80" -DestinationPortRange "80" -SourceAddressPrefix "*" -DestinationAddressPrefix "10.120.0.0/21" -Access Allow -Direction Inbound -Priority 200
$httpsrule = New-AzureRmNetworkSecurityRuleConfig -Name "FrontEnd_HTTPS" -Description "HTTPS Exception for Web frontends" -Protocol Tcp -SourcePortRange "443" -DestinationPortRange "443" -SourceAddressPrefix "*" -DestinationAddressPrefix "10.120.0.0/21" -Access Allow -Direction Inbound -Priority 201
$sshrule = New-AzureRmNetworkSecurityRuleConfig -Name "FrontEnd_SSH" -Description "SSH Exception for Web frontends" -Protocol Tcp -SourcePortRange "22" -DestinationPortRange "22" -SourceAddressPrefix "*" -DestinationAddressPrefix "10.120.0.0/21" -Access Allow -Direction Inbound ` -Priority 203
$nsg = New-AzureRmNetworkSecurityGroup -ResourceGroupName $vNetResourceGroupName -Location $Location -Name $NSGName -SecurityRules $httprule,$httpsrule, $sshrule –Confirm:$false -Force -WarningAction SilentlyContinue | Out-Null
$nsgid = Get-AzureRmNetworkSecurityGroup -Name $NSGName -ResourceGroupName $vNetResourceGroupName -WarningAction SilentlyContinue | Out-Null
Write-Host "Network Security Group creation completed" -ForegroundColor White
}
else
{Write-Host "Skipping NSG Creation" -ForegroundColor White}
}
Function CreateVPN {
New-AzureRmLocalNetworkGateway -Name LocalSite -ResourceGroupName $ResourceGroupName -Location $Location -GatewayIpAddress $LocalNetPip -AddressPrefix $LocalAddPrefix -ErrorAction Stop -WarningAction SilentlyContinue
Write-Host "Completed Local Network GW Creation"
$vpnpip= New-AzureRmPublicIpAddress -Name vpnpip -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Dynamic -ErrorAction Stop -WarningAction SilentlyContinue
$vnet = Get-AzureRmVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -ErrorAction Stop -WarningAction SilentlyContinue
$subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -VirtualNetwork $vnet -WarningAction SilentlyContinue
$vpnipconfig = New-AzureRmVirtualNetworkGatewayIpConfig -Name vpnipconfig1 -SubnetId $subnet.Id -PublicIpAddressId $vpnpip.Id -WarningAction SilentlyContinue
New-AzureRmVirtualNetworkGateway -Name vnetvpn1 -ResourceGroupName $ResourceGroupName -Location $Location -IpConfigurations $vpnipconfig -GatewayType Vpn -VpnType RouteBased -GatewaySku Standard -ErrorAction Stop -WarningAction SilentlyContinue
Write-Host "Completed VNET Network GW Creation"
Get-AzureRmPublicIpAddress -Name vpnpip -ResourceGroupName $ResourceGroupName -WarningAction SilentlyContinue
Write-Host "Configure Local Device with Azure VNET vpn Public IP"
}
Function ConnectVPN {
[PSObject]$gateway1 = Get-AzureRmVirtualNetworkGateway -Name vnetvpn1 -ResourceGroupName $ResourceGroupName -WarningAction SilentlyContinue
[PSObject]$local = Get-AzureRmLocalNetworkGateway -Name LocalSite -ResourceGroupName $ResourceGroupName -WarningAction SilentlyContinue
New-AzureRmVirtualNetworkGatewayConnection -ConnectionType IPSEC  -Name sitetosite -ResourceGroupName $ResourceGroupName -Location $Location -VirtualNetworkGateway1 $gateway1 -LocalNetworkGateway2 $local -SharedKey '4321avfe' -Verbose -Force -RoutingWeight 10
}
Function ProvisionResGrp
{
New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location –Confirm:$false -force -WarningAction SilentlyContinue | Out-Null
}

VerifyProfile
ProvisionResGrp
if($NewVNET -eq "True"){ProvisionNET}
if($NSGEnabled -eq "True"){CreateNSG}
CreateVPN
ConnectVPN