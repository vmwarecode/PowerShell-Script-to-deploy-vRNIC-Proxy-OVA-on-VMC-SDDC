<#
.SYNOPSIS  
    This script helps to deploy vRealize Network Insight Cloud Proxy OVA at VMC SDDC on AWS.

.DESCRIPTION 

    Pre-requisites before running script:
    1) User must open this script and modify 'required user variables`. Refer below. These variables are currently set to "" (blank)
    2) Script should be executed on PowerShell version 6.0 or above

    Script performs below task:
    * Check/Install/Import required powershell modules needed for this script.
    * Download vRealize Network Insight Proxy OVA from public URL
    * Configure Gateway firewall rules on VMC (Management & Compute)
    * Deploy OVA on SDDC
    * Power ON VM
    * Verify VM is up and connected to vRealize Network Insight Cloud.

    More Info:
     -------------------------
    | Required User variables |
     -------------------------

    # Below information from VMware cloud services portal after login

    VMCOrgName                   - VMC Org Name e.g. 'My VMC Org'
    VMCRefreshToken              - API Token - Navigate to `My Account` -> `API Tokens`
    VMCSDDCName                  - SDDC name where VM will be deployed
    VMNetwork                    - Network at which VM should be attached

    # Below information is as per your preference for OVA deployment

    VMName                       - VM name for proxy vm, default (vrnic-proxy-vm)
    VRNIProxySecretKey           - Get this from vRealize Network Insight Cloud portal - `Setting`s - `Install and support` - button `Add Collector` - Copy key by clicking `copy` icon
    VRNIVmStaticIP               - Static IP for vm e.g. 192.168.0.10
    VRNIVmNetmask                - Netmask e.g. 255.255.255.0
    VRNIVmGatewayIP              - Gateway IP e.g. 19.168.0.1
    VRNIVmDNS                    - Space seperated DNS nameserver ip addresses e.g. '8.8.8.8 4.2.2.2'
    VRNIVmDomainSearch           - domain search determines which domain is appended for dns lookups e.g. example.domain.com
    VRNIVmNtpIPOrFqdns           - Spece seperated IP addresses or ntp fqdn's e.g. '192.168.0.253 0.ubuntu.pool.ntp.org'
    VRNIVmUserSupportSshPassword - Password for vRNI 'support' user to ssh
    VRNIVmUserCLISshPassword     - Password for vRNI cli 'consoleuser' user to ssh

     -------------------------
    | Optional User variables |
     -------------------------
     Cluster                     - VMC cluster name, 'Cluster-1' (default)
     VMCVMFolderName             - VM folder where vm will be deployed, Workloads (default)
     VMCResourcePoolName         - Resource pool, 'Compute-ResourcePool' (default)
     VMCDatastoreName            - Datastore, 'WorkloadDatastore' default)

     VMDeploymentSize            - Deployment Size of vRNI Proxy VM, "medium" (default), "large", "extra_large". 
                                   More Info "Recommendation for the Collector Deployment" at below url
                                   https://docs.vmware.com/en/VMware-vRealize-Network-Insight/5.0/com.vmware.vrni.install.doc/GUID-F4F34425-C40D-457A-BA65-BDA12B3ABE45.html

     ---------------------------------------------
    | Required Modules (Auto Installed by Scirpt) |
     ---------------------------------------------
     VMware.VMC
     VMware.PowerCLI
     VMware.VMC.NSXT   - Available from below URL
                         https://github.com/lamw/PowerCLI-Example-Scripts/tree/master/Modules/VMware.VMC.NSXT
     powershell-yaml


.NOTES  
    Author     : sharmaarun@vmware.com
                 sourabhv@vmware.com
    Company    : VMware, Inc.
    Version    : 1.0.0


.PARAMETER No Parameters
#>
[CmdLetBinding()]
param(
)


# Please fill required user variables below as per your environment
# #### (Required) #### - User variables - Fill below variables. See description above.
$VMCOrgName = ""
$VMCRefreshToken = ""
$VMCSDDCName = ""
$VMNetwork = ""
$VRNIProxySecretKey = ""
$VRNIVmStaticIP = ""
$VRNIVmNetmask = ""
$VRNIVmGatewayIP = ""
$VRNIVmDNS = ""
$VRNIVmDomainSearch = ""
$VRNIVmNtpIPOrFqdns = ""
$VMName = ""
$VRNIVmUserSupportSshPassword = ""
$VRNIVmUserCLISshPassword = ""

# #### (Optional) #### - User variables - Already set with default but you can modify if you want as per environment.
$Cluster = "Cluster-1"
$VMCVMFolderName = "Workloads" 
$VMCResourcePoolName = "Compute-ResourcePool"
$VMCDatastoreName = "WorkloadDatastore"
$VMDeploymentSize = "medium"         ## 'medium' (default) or 'large' or 'extra_large'




#!!! You shouldn't have to change anything below this point !!!

#Requires -Version 6.0

Set-PowerCLIConfiguration -InvalidCertificateAction ignore -confirm:$false >$null
$ErrorActionPreference = 'Stop'
$SupportUser = "support"
$CspPortal = "https://console.cloud.vmware.com"
$InfoFromCspPortalMsg = "You can get from $CspPortal portal"
$InfoFromYourEnvironment = "Please fill this variable as per your environment"
$vcConnection = $null
$vmcConnection = $null
$vmcConfig = '
- group: &group1
    display_name: "a-vrni-proxy-grp"
    gateway_type: MGW
- group: &group2
    display_name: "a-vrni-proxy-grp"
    gateway_type: CGW
- service: &service1
    display_name: "vrni_proxy_tcp_80"
    destination_ports: [80]
    protocol: TCP
- service: &service2
    display_name: "vrni_proxy_tcp_443"
    destination_ports: [443]
    protocol: TCP
- firewall_rule: &firewall_rule1
    display_name: vrni_proxy_connect_80
    source_groups: [a-vrni-proxy-grp]
    destination_groups: ["ANY"]
    services: [vrni_proxy_tcp_80]
    action: ALLOW
    gateway_type: CGW
    scope: [cgw]
    seq_no: 1
- firewall_rule: &firewall_rule2
    display_name: vrni_proxy_connect_443
    source_groups: [a-vrni-proxy-grp]
    destination_groups: ["ANY"]
    services: [vrni_proxy_tcp_443]
    action: ALLOW
    gateway_type: CGW
    scope: [cgw]
    seq_no: 2
- firewall_rule: &firewall_rule3
    display_name: vrni_proxy_to_NSX
    source_groups: [a-vrni-proxy-grp]
    destination_groups: [NSX Manager]
    services: [HTTPS]
    action: ALLOW
    gateway_type: MGW
    scope: [mgw]
    seq_no: 1
- firewall_rule: &firewall_rule4
    display_name: vrni_proxy_to_vc
    source_groups: [a-vrni-proxy-grp]
    destination_groups: [vCenter]
    services: [HTTPS]
    action: ALLOW
    gateway_type: MGW
    scope: [mgw]
    seq_no: 2
'

$ReqParamMsg = "`nPlese open this script on any editor and fill the (Required) user variable and rerun script !`nYou can get help by running 'get-help deploy_ova_on_vmc_sddc.ps1 '  "
Write-Host "`n`n`n"
Write-Host "Running vRNIC Proxy OVA deployment script to deploy Proxy at VMC on AWS" -ForegroundColor Blue

Write-Host "`n[Step 1]: Started - validating required parameters" -ForegroundColor DarkYellow

if ($VRNIProxySecretKey -eq "") { Write-Host "Found VRNIProxySecretKey required variable blank, You can get by logging into vRealize Network Insight Cloud portal !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMCOrgName -eq "") { Write-Host "Found VMCOrgName required variable blank, $InfoFromCspPortalMsg !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMCRefreshToken -eq "") { Write-Host "Found VMCRefreshToken required variable blank, $InfoFromCspPortalMsg !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMCSDDCName -eq "") { Write-Host "Found VMCSDDCName required variable blank, $InfoFromCspPortalMsg !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMName -eq "") { Write-Host "Found VMName blank, $InfoFromYourEnvironment !. e.g. vrni-proxy-vm`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmStaticIP -eq "") { Write-Host "Found VRNIVmStaticIP required variable blank, $InfoFromYourEnvironment !. e.g. 192.168.0.10`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmNetmask -eq "") { Write-Host "Found VRNIVmNetmask required variable blank, $InfoFromYourEnvironment !. e.g. 255.255.255.0`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmGatewayIP -eq "") { Write-Host "Found VRNIVmGatewayIP required variable blank, $InfoFromYourEnvironment !. e.g. 192.168.0.1`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmDNS -eq "") { Write-Host "Found VRNIVmDNS required variable blank, $InfoFromYourEnvironment !. e.g. '8.8.8.8 4.2.2.4'`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmDomainSearch -eq "") { Write-Host "Found VRNIVmDomainSearch required variable blank, $InfoFromYourEnvironment !. e.g. 'example.domain.com'`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmNtpIPOrFqdns -eq "") { Write-Host "Found VRNIVmNtpIPOrFqdns required variable blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmUserSupportSshPassword -eq "") { Write-Host "Found VRNIVmUserSupportSshPassword blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VRNIVmUserCLISshPassword -eq "") { Write-Host "Found VRNIVmUserCLISshPassword blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($Cluster -eq "") { Write-Host "Found Cluster blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMCVMFolderName -eq "") { Write-Host "Found VMCVMFolderName blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMCResourcePoolName -eq "") { Write-Host "Found VMCResourcePoolName blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMCDatastoreName -eq "") { Write-Host "Found VMCDatastoreName blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}

if ($VMNetwork -eq "") { Write-Host "Found VMNetwork required variable blank, $InfoFromYourEnvironment !`n $ReqParamMsg" -ForegroundColor Magenta; exit}


function CleanExit {
    Disconnect-VIServer -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    If ($global:DefaultVMCServers.IsConnected) {
        Disconnect-Vmc -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    exit
}

function DownloadFile($url, $targetFile)
{
   $uri = New-Object "System.Uri" "$url"
   $request = [System.Net.HttpWebRequest]::Create($uri)
   $request.set_Timeout(15000) #15 second timeout
   $response = $request.GetResponse()
   $totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
   $responseStream = $response.GetResponseStream()
   $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
   $buffer = new-object byte[] 10KB
   $count = $responseStream.Read($buffer,0,$buffer.length)
   $downloadedBytes = $count
   while ($count -gt 0)
   {
       $targetStream.Write($buffer, 0, $count)
       $count = $responseStream.Read($buffer,0,$buffer.length)
       $downloadedBytes = $downloadedBytes + $count
       Write-Progress -activity "Downloading file '$($url.split('/') | Select -Last 1)'" -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength)  * 100)
   }
   Write-Progress -activity "Finished downloading file '$($url.split('/') | Select -Last 1)'"
   $targetStream.Flush()
   $targetStream.Close()
   $targetStream.Dispose()
   $responseStream.Dispose()
}

function get_config_detials
{
	try
	{
        $content = $null
		foreach ($line in $vmcConfig) { $content = $content + "`n" + $line }
		$config_yaml = ConvertFrom-YAML $content
		return $config_yaml
	}
	catch [Exception]
	{
        Write-Host $_.Exception.GetType().FullName, $_.Exception.Message
		Write-Host "`n VMC Config defination been modified or its not in expected yml template format `n" -ForegroundColor Red
        CleanExit
	}
}

function configure_fw($config_yaml)
{	

    try {
	    # Connect NSXT policy manager using token for respective sddc and org
        Write-Host "`tConnecting NSXT server.."
	    Connect-NSXTProxy -RefreshToken $VMCRefreshToken -OrgName $VMCOrgName -SDDCName $VMCSDDCName > $null
        Write-Host "`tConnected NSXT server"
    }
    catch [Exception]
    {
        Write-Host $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "`tFailed to connect NSXT server" -ForegroundColor Red
        CleanExit
    }

    try {
	    # Create NSXT group for proxy deployed
	    foreach ($grp in $config_yaml.group)
	    {
            $gp_status = $null
            Write-Verbose -Message  ([string]::Format("`tChecking NSXTGroup - '{0}' gateway type '{1}'", $grp.display_name, $grp.gateway_type))
		    $gp_status = Get-NSXTGroup -GatewayType $grp.gateway_type -Name $grp.display_name -ErrorVariable ProcessError -ErrorAction Stop
		    if ($gp_status)
		    {
                Write-Host ([string]::Format("`tNSXTGroup '{0}' already exist, skipping group creation", $grp.display_name))
                Write-Host ([string]::Format("`tWARNING - If you have changed static IP address in this script in variable 'VRNIVmStaticIP' and ran script then the group {0} will not contain new IP address. You might need to delete this group and re-run script", $grp.display_name))  -ForegroundColor DarkMagent
			    continue
		    }
            Write-Host  ([string]::Format("`tCreating NSXTGroup - '{0}' gateway type '{1}' members [{2}]", $grp.display_name, $grp.gateway_type, $VRNIVmStaticIP))
            $result = $null
		    $result = New-NSXTGroup -GatewayType $grp.gateway_type -Name $grp.display_name -IPAddress $VRNIVmStaticIP  -ErrorVariable ProcessError -ErrorAction Stop
		    Write-Verbose -Message "`t$result"
	    }
	
	    # Define service and create
	    foreach ($srv in $config_yaml.service)
	    {
            Write-Verbose -Message ([string]::Format("`tChecking Service - '{0}'", $srv.display_name))
            $srv_status = $null
		    $srv_status = Get-NSXTServiceDefinition -Name $srv.display_name  -ErrorVariable ProcessError -ErrorAction Stop
		    if ($srv_status)
		    {
                Write-Host ([string]::Format("`tService already exist, skipping service creation for - '{0}'", $srv.display_name))
			    Write-Verbose -Message "`t$srv_status"
			    continue
		    }
            Write-Host ([string]::Format("`tCreating Service - '{0}'", $srv.display_name))
            $result = $null
		    $result = New-NSXTServiceDefinition -Name $srv.display_name -Protocol $srv.protocol -DestinationPorts $srv.destination_ports  -ErrorVariable ProcessError -ErrorAction Stop
		    Write-Verbose -Message $result
	    }
	
	    # Create Firewall rules
	    foreach ($rule in $config_yaml.firewall_rule)
	    {
            Write-Verbose -Message ([string]::Format("`tChecking NSXTFirewall rule name - '{0}' on gateway type '{1}'", $rule.display_name, $rule.gateway_type))
            $rule_status = $null
		    $rule_status = Get-NSXTFirewall -GatewayType $rule.gateway_type -Name $rule.display_name  -ErrorVariable ProcessError -ErrorAction Stop
		    if ($rule_status)
		    {
                Write-Host ([string]::Format("`tFirewall rule '{0}' on gateway type '{1}' already exist, skipping Firewall rule creation", $rule.display_name, $rule.gateway_type))
			    Write-Verbose -Message "`t$rule_status"
			    continue
		    }
            Write-Host ([string]::Format("`tCreating NSXTFirewall rule '{0}' on gateway type '{1}'", $rule.display_name, $rule.gateway_type))
            $result = $null
		    $result = New-NSXTFirewall -GatewayType $rule.gateway_type -Name $rule.display_name -SourceGroup $rule.source_groups -DestinationGroup $rule.destination_groups -Service $rule.services -SequenceNumber $rule.seq_no -Action $rule.action  -ErrorVariable ProcessError -ErrorAction Stop
		    Write-Verbose -Message "`t$result"
	    }
	    Write-Host "`n`tFirewall rules configured succesfully`n"
    }
    catch [Exception] {
        Write-Host $_.Exception.GetType().FullName, $_.Exception.Message -ForegroundColor Red
        Write-Host "`t$ProcessError"
        Write-Host "`n`tFailed to configure firewall" -ForegroundColor Red
        CleanExit
    }
}

function printSupportErrorMsg() {
    Write-Host "`n`tvRNIC tenant proxy VM failed to configure with vRealize Network Insight Cloud" -ForegroundColor Red
    Write-Host "`tTo troubleshoot, login to vCenter -> Open VM console for '$VMName'" -ForegroundColor Yellow
    Write-Host "`tLogin to vRNIC CLI using user 'consoleuser', password printed on console or try '$VRNIVmUserCLISshPassword'" -ForegroundColor Yellow
    Write-Host "`tTry below cli commands to re-configure and verify status" -ForegroundColor Yellow
    Write-Host "`tcommand 'setup' to rerun the configuration" -ForegroundColor Yellow
    Write-Host "`tcommand 'show-connectivity-status' to check connection to VMware cloud" -ForegroundColor Yellow
    Write-Host "`tcommand 'show-config' to check connection to VMware cloud" -ForegroundColor Yellow
    Write-Host "`t`nContact VMware support for more help!" -ForegroundColor Yellow
}

# Download OVA as proxy.ova if not present on script root directory.
$OvaUrl = "https://s3-us-west-2.amazonaws.com/vrni-packages-archive-symphony/latest/VMWare-Network-Insight-Collector.ova"
$OvaFile = "$PSScriptRoot\proxy.ova"

Write-Host "`n[Step 2]: Download or use existing OVA" -ForegroundColor DarkYellow
$ovaPresent = Test-Path $OvaFile -PathType Leaf
if (!$ovaPresent) {
    Write-Host "`tDownloading OVA.."
    $start_time = Get-Date
    DownloadFile $OvaUrl $OvaFile
    Write-Output "`tTime taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"
} else {
    Write-Host "`tUsing existing downloaded OVA: $OvaFile"
}

# Modules check/install/import

Write-Host "`n[Step 3]: Checking required powershell modules present or not, installing and importing if required"  -ForegroundColor DarkYellow
$reqModules = @( "VMware.PowerCLI", "VMware.VMC", "powershell-yaml" )
$question = 'Are you sure you want to proceed?'
$choices  = '&Yes', '&No'
foreach ($module in $reqModules) {
    if (Get-Module -ListAvailable -Name $module) {
        Write-Verbose -Message  "Module $module exists"
    }
    else 
    {
        $decision = $Host.UI.PromptForChoice("PowerShell module: $module not present. Script will install module and continue.", 
                                             "Are you sure you want to proceed?", 
                                             $choices, 
                                             0)
        if ($decision -eq 0) {
            Write-Host "`n"
            Install-Module -Name $module -Scope CurrentUser -AllowClobber -AcceptLicense -Confirm:$false -Repository PSGallery -ErrorAction Stop
        } else {
            Write-Host 'You have cancelled PowerShell module $module install execution step.' -ForegroundColor Red
            Write-Host "Please install manually using below command and re-run script" -ForegroundColor Yellow
            Write-Host "`'Install-Module -Name $module -scope allusers -AllowClobber'`n" -ForegroundColor Yellow
            CleanExit
        }
    }
    try {
        Write-Verbose -Message "Importing Module $module"
        Import-Module -Name $module -ErrorVariable ErrVar -WarningAction SilentlyContinue –NoClobber 3>$null
    }
    catch [Exception]
	{
        if ($module -notcontains "VMware.PowerCLI") {
            Write-Host $_.Exception.GetType().FullName, $_.Exception.Message
	        Write-Host "`nThere was Warning on import of module $module, Ignoring `n" -ForegroundColor Red
            Write-Host "$ErrVar"
        }
	}
}

try
{
    Write-Verbose -Message "Dwonloading VMware.VMC.NSXT module"
    $ModBaseUrl = "https://raw.githubusercontent.com/lamw/PowerCLI-Example-Scripts/master/Modules/VMware.VMC.NSXT"
    New-Item -ItemType Directory -Path "$PSScriptRoot\VMware.VMC.NSXT" -ErrorAction SilentlyContinue
    DownloadFile "$ModBaseUrl/VMware.VMC.NSXT.psd1" "$PSScriptRoot\VMware.VMC.NSXT\VMware.VMC.NSXT.psd1"
    DownloadFile "$ModBaseUrl/VMware.VMC.NSXT.psm1" "$PSScriptRoot\VMware.VMC.NSXT\VMware.VMC.NSXT.psm1"
    Write-Verbose -Message "Dwonloaded VMware.VMC.NSXT module"
    Write-Verbose -Message "Importing module VMware.VMC.NSXT"
	Import-Module $PSScriptRoot\VMware.VMC.NSXT\VMware.VMC.NSXT.psd1 -ErrorVariable ErrVar -OutVariable OutVar
}
catch
{
     Write-Host "`tModules import failed for VMware.VMC.NSXT , Please download it from below Location`n"  -ForegroundColor Red
     Write-Host "`t$ErrVar"  -ForegroundColor Red
     Write-Host "`t$OutVar"  -ForegroundColor Red
     Write-Host "`thttps://github.com/lamw/PowerCLI-Example-Scripts/tree/master/Modules"
     CleanExit
}

Write-Host "`n[Step 4]: Started - Checking connecitivity with VMC & VC server and fetching info"  -ForegroundColor DarkYellow
try {
    Write-Host "`tConnecting VMC server.."
    Connect-Vmc -refreshtoken $VMCRefreshToken > $null
    Write-Host "`tConnected VMC server"
}
catch {
    Write-Host "`tFailed to connect VMC. Please check, there is internet connectivity from where you are running script"  -ForegroundColor Red
    Write-Host "`t$ErrVar"
    Write-Host "`t$OutVar"
    CleanExit
}

# Communicate with VMC and fetch org information
Write-Host "`tFetching VMC organization information.."
$VMCOrgId = $null
$selectedOrg = Get-VMCOrg -Name $VMCOrgName

if ($selectedOrg -eq $null) {
    Write-Output "`tOrg named '$VMCOrgName' not found. Please check, if correct org name entered on variable VMCOrgName !"  -ForegroundColor Red
    break
} else {
    $VMCOrgId = $selectedOrg.id
}

Write-Host "`tVMC Org ID: $VMCOrgId"

$selectedSddc = Get-VMCSDDC -Org $VMCOrgName -Name $VMCSDDCName

if ($selectedSddc -eq $null) {
    Write-Host "`tVMCSDDC '$VMCSDDCName' not found. Please check, if correct SDDC Name on variable VMCSDDCName"  -ForegroundColor Red
    CleanExit
}

$VCIP = $selectedSddc.resource_config.vc_management_ip
$VCUsername = $selectedSddc.resource_config.cloud_username
$VCPassword = $selectedSddc.resource_config.cloud_password

Write-Host "`tConnecting VCenter Server: private IP - " -NoNewline
Write-Host "$VCIP" -ForegroundColor Magenta -BackgroundColor Yellow -NoNewline
Write-Host ", Username - $VCUsername" 

# Connect VIServer
try {
    $vcConnection = Connect-VIServer -Server $VCIP -Protocol https -User $VCUsername -Password $VCPassword -ErrorVariable ErrVar -OutVariable OutVar
    Write-Host "`tConnected VCenter Server"
}
catch {
    Write-Host "`tFailed to connect VCenter, Please check vCenter Ip [$VCIP] is reachable over HTTPS(443)"  -ForegroundColor Red
    Write-Host "$ErrVar" -ForegroundColor Red
    Write-Host "$OutVar" -ForegroundColor Red
    CleanExit
}

# OVA deployment
$ovfconfig = Get-OvfConfiguration $OvaFile
$VMCResourcePool = Get-ResourcePool $VMCResourcePoolName | Select -first 1
$VMCDatastore = Get-Datastore $VMCDatastoreName | Select -first 1
$VMCVMFolder = Get-Folder $VMCVMFolderName | Select -first 1
$VMHost = Get-Cluster $Cluster | Get-VMHost -State Connected | Sort MemoryGB | Select -first 1

if ($VMHost -eq $null) {
    Write-Host "No Host found where VM can be deployed, Exiting..." -ForegroundColor Red
    CleanExit
}

$ovfconfig.DeploymentOption.value = $VMDeploymentSize
Write-Host "`n"
Write-Host "`e[4mInventory location where VM will be deployed:`e[24m" -ForegroundColor Blue
Write-Host "`tvCenter Private IP - $VCIP" -ForegroundColor Blue
Write-Host "`tVMCOrgName - $VMCOrgName" -ForegroundColor Blue
Write-Host "`tVMCSDDCName - $VMCSDDCName" -ForegroundColor Blue
Write-Host "`tVRNIVmStaticIP - $VRNIVmStaticIP" -ForegroundColor Blue
Write-Host "`tVRNIVmNetmask - $VRNIVmNetmask" -ForegroundColor Blue
Write-Host "`tVRNIVmGatewayIP - $VRNIVmGatewayIP" -ForegroundColor Blue
Write-Host "`tVRNIVmDNS - $VRNIVmDNS" -ForegroundColor Blue
Write-Host "`tVRNIVmDomainSearch - $VRNIVmDomainSearch" -ForegroundColor Blue
Write-Host "`tVRNIVmNtpIPOrFqdns - $VRNIVmNtpIPOrFqdns" -ForegroundColor Blue
Write-Host "`tCluster: $Cluster" -ForegroundColor Blue
Write-Host "`tVMHost: $VMHost" -ForegroundColor Blue
Write-Host "`tDatastore: $VMCDatastore" -ForegroundColor Blue
Write-Host "`tNetwork: $VMNetwork" -ForegroundColor Blue
Write-Host "`tResource-Pool: $VMCResourcePool" -ForegroundColor Blue
Write-Host "`tVM Folder: $VMCVMFolder" -ForegroundColor Blue
Write-Host "" -ForegroundColor Blue
Write-Host "`e[4mBelow firewall changes will be done by script:`e[24m" -ForegroundColor Blue
Write-Host "`tNSXT-Group: Name: vrni-proxy-grp, Members: [$VRNIVmStaticIP]" -ForegroundColor Blue
Write-Host "`tGateway Firewall" -ForegroundColor Blue
Write-Host "`t`tCompute Gateway rules" -ForegroundColor Blue
Write-Host "`t`t Rule1 - Name: vrni_proxy_connect_80, Source: vrni-proxy-grp, destination: Any, Services: 80, Action: ALLOW" -ForegroundColor Blue
Write-Host "`t`t Rule2 Name: vrni_proxy_connect_443, Source: vrni-proxy-grp, destination: Any, Services: 443, Action: ALLOW" -ForegroundColor Blue
Write-Host "`t`tManagement Gateway rules" -ForegroundColor Blue
Write-Host "`t`t Rule3 Name: vrni_proxy_to_NSX, Source: vrni-proxy-grp, destination: NSX Manager, Services: 443, Action: ALLOW" -ForegroundColor Blue
Write-Host "`t`t Rule4 Name: vrni_proxy_to_vc, Source: vrni-proxy-grp, destination: vCenter, Services: 443, Action: ALLOW" -ForegroundColor Blue

$title    = 'Please read above summary and cofirm to proceed'
$question = 'Are you sure you want to proceed?'
$choices  = '&Yes', '&No'

$decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
if ($decision -eq 0) {
    Write-Host "`n"
} else {
    Write-Host 'You have cancelled the execution'  -ForegroundColor Red
    CleanExit
}

Write-Host "`n[Step 5]: Started - Configuring firewall"  -ForegroundColor DarkYellow

# vmc firewall rules setup
$config_yaml = get_config_detials
configure_fw $config_yaml

# Deployment config
$DeploymentConfig = ([string]::Format("VRNICUSTOMPROP:IP_Address={0}:Netmask={1}:Default_Gateway={2}:DNS={3}:Domain_Search={4}:NTP={5}:SSH_User_Password={6}:CLI_User_Password={7}:Auto-Configure=True:VRNICUSTOMPROP",
             $VRNIVmStaticIP,
             $VRNIVmNetmask,
             $VRNIVmGatewayIP,
             $VRNIVmDNS,
             $VRNIVmDomainSearch,
             $VRNIVmNtpIPOrFqdns,
             $VRNIVmUserSupportSshPassword,
             $VRNIVmUserCLISshPassword
             ))

$ovfconfig.Common.App_Init.value = $DeploymentConfig
$ovfconfig.Common.Proxy_Shared_Secret.value = $VRNIProxySecretKey
$ovfconfig.NetworkMapping.VM_Network.value = $VMNetwork

# Check existing vm with same name
$ExistingVm = (Get-VM -Name $VMName -ErrorAction Ignore)
if ($ExistingVm -ne $null) {
    Write-Host "VM already present with name '$VMName'. Please set a new name on user variable 'VMName'" -ForegroundColor Red
    CleanExit
}

Write-Host "`n[Step 6]: Started - Deploying OVA as VM: '$VMName'"  -ForegroundColor DarkYellow

Try {
    Import-VApp -Source $OvaFile -OvfConfiguration $ovfconfig -Name $VMName -VMHost $vmhost -Datastore $VMCDatastore -DiskStorageFormat thin -Location $VMCResourcePool -InventoryLocation $VMCVMFolder -ErrorAction Stop -ErrorVariable Errvar -OutVariable OutVar > $null
    Write-Verbose -Message "`tImport-App finished"
}
Catch {
    Write-Host "`tImport OVA failed, Error: $ErrVar"
    Write-Host "`tImport OVA Output (if any): $OutVar"
    CleanExit
}

Write-Host "`tDeployed OVA"

Write-Host "`n[Step 7]: Started - Post operations"  -ForegroundColor DarkYellow

# Setting mem,cpu reservation to 0 is sole for development test purpose
# TODO: Remove below reservation change befor publishing
$Reservations = Get-VM -Name $VMName | Get-VMResourceConfiguration | Select VM, CpuReservationMhz, MemReservationGB
Get-VM -Name $VMName | Get-VMResourceConfiguration |Set-VMResourceConfiguration -MemReservationMB 0 > $null
Get-VM -Name $VMName | Get-VMResourceConfiguration |Set-VMResourceConfiguration -CpuReservationMhz 0 > $null

# Power on vm
$VM = get-vm -Name $VMName
if ($VM.PowerState -eq "PoweredOn") {
    Write-Host "`tVM '$VMName' already powered on"
} Else {
    Write-Host "`tPowering ON VM: '$VMName'"
    Start-VM $VM > $null
}

Write-Host "`tWaiting few secs for VM to come up.."
Start-Sleep -s 5

function checkPing($ip) {
    $status = Test-Connection $ip -Quiet -Count 1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue 6>$null
    return $status
}

$elapsedTime = [system.diagnostics.stopwatch]::StartNew()
Write-Host "`tWaiting till VM '$VMName' is reachable.."
$Ping = checkPing($VRNIVmStaticIP)
foreach ($_ in 1..36) {
    write-progress -activity "Connecting (ping) '$VRNIVmStaticIP' ... " -status $elapsedtime.elapsed.ToString().SubString(0,8)
    Start-Sleep -s 3
    $Ping = checkPing($VRNIVmStaticIP)
    if ($Ping) {break}
}

if ($Ping) {
    Write-Host "`n`tVM '$VMName' - ping works !" -ForegroundColor Green
} 
else {
    Write-Host "`n`tError - VM '$VMName' - Not reachable, ping fails - '$VRNIVmStaticIP'" -ForegroundColor Red
    printSupportErrorMsg
    CleanExit
}

Write-Host "`tWaiting few secs for VM to be completely up..."
Start-Sleep -s 10

# Invoke script on appliance and print output, parse and wait till it is configured
function checkPairingStatus() {
    $cmd = "sudo ls /home/ubuntu/build-target/deployment/.registered"
    $status = Invoke-VMScript -VM $VMName -ScriptText $cmd -GuestUser  $SupportUser -GuestPassword $VRNIVmUserSupportSshPassword -ErrorAction Ignore
    return $status
}

$elapsedTime = [system.diagnostics.stopwatch]::StartNew()
Write-Host "`tChecking if VM '$VMName' configured with vRealize Network Insight Cloud... "
$configured = checkPairingStatus
foreach ($_ in 1..36) {
    write-progress -activity "Checking if VM '$VMName' configured with vRealize Network Insight Cloud... " -status $elapsedtime.elapsed.ToString().SubString(0,8)
    Start-Sleep -s 3
    $configured = checkPairingStatus
    if ($configured.ExitCode -eq 0) {break}
}

if ($configured.ExitCode -eq 0) {
    Write-Host "`n`tvRNI Proxy successfully configured with vRealize Network Insight Cloud !! All Set." -ForegroundColor Green
}
else {
    printSupportErrorMsg
    CleanExit
}


Write-Host "`n`tNow you can go to https://console.cloud.vmware.com to access 'vRealize Network Insight service' and see new collector added under 'Settings'." -ForegroundColor Green


CleanExit

