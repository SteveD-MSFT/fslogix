#$resourceGroupName = "azure-eastus-rg"
#$storageAccountName = "scdeusavdprofiles"

function Set-StorageAccountAadKerberosADProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$false, Position=2)]
        [string]$Domain
    )  

    $AzContext = Get-AzContext;
    if ($null -eq $AzContext) {
        Write-Error "No Azure context found.  Please run Connect-AzAccount and then retry." -ErrorAction Stop;
    }

    $AdModule = Get-Module ActiveDirectory;
     if ($null -eq $AdModule) {
        Write-Error "Please install and/or import the ActiveDirectory PowerShell module." -ErrorAction Stop;
    }	

    if ([System.String]::IsNullOrEmpty($Domain)) {
        $domainInformation = Get-ADDomain
        $Domain = $domainInformation.DnsRoot
    } else {
        $domainInformation = Get-ADDomain -Server $Domain
    }

    $domainGuid = $domainInformation.ObjectGUID.ToString()
    $domainName = $domainInformation.DnsRoot
    $domainSid = $domainInformation.DomainSID.Value
    $forestName = $domainInformation.Forest
    $netBiosDomainName = $domainInformation.DnsRoot
    $azureStorageSid = $domainSid + "-123454321";

    Write-Verbose "Setting AD properties on $StorageAccountName in $ResourceGroupName : `
        EnableActiveDirectoryDomainServicesForFile=$true, ActiveDirectoryDomainName=$domainName, `
        ActiveDirectoryNetBiosDomainName=$netBiosDomainName, ActiveDirectoryForestName=$($domainInformation.Forest) `
        ActiveDirectoryDomainGuid=$domainGuid, ActiveDirectoryDomainSid=$domainSid, `
        ActiveDirectoryAzureStorageSid=$azureStorageSid"

    $Subscription =  $AzContext.Subscription.Id;
    $ApiVersion = '2021-04-01'

    $Uri = ('https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}?api-version={3}' `
        -f $Subscription, $ResourceGroupName, $StorageAccountName, $ApiVersion);

    $json=
        @{
            properties=
                @{azureFilesIdentityBasedAuthentication=
                    @{directoryServiceOptions="AADKERB";
                        activeDirectoryProperties=@{domainName="$($domainName)";
                                                    netBiosDomainName="$($netBiosDomainName)";
                                                    forestName="$($forestName)";
                                                    domainGuid="$($domainGuid)";
                                                    domainSid="$($domainSid)";
                                                    azureStorageSid="$($azureStorageSid)"}
                                                    }
                    }
        };  

    $json = $json | ConvertTo-Json -Depth 99

    $token = $(Get-AzAccessToken).Token
    $headers = @{ Authorization="Bearer $token" }

    try {
        Invoke-RestMethod -Uri $Uri -ContentType 'application/json' -Method PATCH -Headers $Headers -Body $json
    } catch {
        Write-Host $_.Exception.ToString()
        Write-Host "Error setting Storage Account AD properties.  StatusCode:" $_.Exception.Response.StatusCode.value__ 
        Write-Host "Error setting Storage Account AD properties.  StatusDescription:" $_.Exception.Response.StatusDescription
        Write-Error -Message "Caught exception setting Storage Account AD properties: $_" -ErrorAction Stop
    }
}

#Get config info
$config = '..\run.config.default.json'
$jConfig = Get-Content $config | ConvertFrom-Json
$tenant = $jConfig.args.tenant
$sub = $jConfig.args.subscription
$shares = $jConfig.shares

Write-Host "Tenant: $tenant"
Write-Host "Resource Group: $rgName"

# Login
If (!(Get-AzContext)) {
    Write-Host "Please login to your Azure account"
    Connect-AzAccount -Tenant $tenant -Subscription $sub
}

# Iterate over shares and configure
foreach ($share in $shares) {

    #File Share
    $storageAccount           = $share.storageAccountName
    $storagelocation          = $share.location
    $storageRGName            = $share.rgName
    $storageSKU               = $share.skuName
    $storageShareName         = $share.shareName
    $storageShareDomain       = $share.shareDomain
    $smbElevatedContributor   = $share.smbElevatedContributor
    $smbContributor           = $share.smbContributor #TODO
    $ntfsUsers                = $share.ntfsUsers
    $ntfsAdmins               = $share.ntfsAdmins
    $adDomain                 = $share.adDomain



    Write-Host "-=== Creating Resource Group ===-"
    Get-AzResourceGroup -Name $storageRGName -ErrorVariable noRG -ErrorAction SilentlyContinue
    if ($noRG) {
        New-AzResourceGroup -Name $storageRGName -Location $storagelocation
    }

    #Configure File share
    Write-Host "-=== Configuring Container Storage ===-"
    Write-Host "Container Storage: CREATING $storageAccount and $storageShareName in $storageRGName ($storagelocation)"

    #dirty :(
    try {
        Get-AzStorageAccount -ResourceGroupName $storageRGName -name $storageAccount -ErrorAction Stop | Out-Null
        Write-Host "Container Storage: (SKIPPING) $storageAccount storage account already exists."
    }
    catch {
        Write-Host "Container Storage: (CREATING) $storageAccount storage account in $storagelocation."
        #New-AzStorageAccount -StorageAccountName $storageAccount -location $storagelocation -ResourceGroupName $storageRGName -SkuName $storageSKU -EnableAzureActiveDirectoryDomainServicesForFile $true -Verbose  
        New-AzStorageAccount -StorageAccountName $storageAccount -location $storagelocation -ResourceGroupName $storageRGName -SkuName $storageSKU -Verbose
    }

    
    #dirty :(
    #Create share
    try {
        Get-AzRmStorageShare -ResourceGroupName $storageRGName -StorageAccountName $storageAccount -ShareName $storageShareName -ErrorAction Stop\
        Write-Host "File Share: (SKIPPING) $storageShareName already exists."
    }
    catch {
        Write-Host "File Share: (CREATING) $storageShareName in $storageAccount."
        New-AzRmStorageShare -StorageAccountName $storageAccount -name $storageShareName -ResourceGroupName $storageRGName
    }

    #Share Permissions
    Write-Host "-===== ASSIGN: AZURE AD ROLES =====-"
    #Constrain the scope to the target file share
    $scope = "/subscriptions/" + $sub + "/resourceGroups/" + $storageRGName + "/providers/Microsoft.Storage/storageAccounts/" + $storageAccount + "/fileServices/default/fileshares/" + $storageShareName
   
    #Elevated SMB Contributor
    $group = Get-AzAdGroup -DisplayName $smbElevatedContributor
    $id = $group.Id

    #get current roles
    #$roles = Get-AzRoleAssignment -objectID $id
    
    $newRole = "Storage File Data SMB Share Elevated Contributor"
    #dirty
    Write-Host "ASSIGNING $newRole to $smbElevatedContributor."
    New-AzRoleAssignment -objectID $id -RoleDefinitionName $newRole -Scope $scope -ErrorAction SilentlyContinue

    #SMB Contributor
    $group = Get-AzAdGroup -DisplayName $smbContributor
    $id = $group.Id

    $newRole = "Storage File Data SMB Share Contributor" 
    Write-Host "ASSIGNING $newRole to $smbContributor."
    New-AzRoleAssignment -objectID $id -RoleDefinitionName $newRole -Scope $scope -ErrorAction SilentlyContinue

    Set-StorageAccountAadKerberosADProperties -ResourceGroupName $storageRGName -StorageAccountName $storageAccount

    #NTFS Perms
    Write-Host "-===== CONFIG: NTFS =====-"
    # Mount share
    #$saKey = (Get-AzStorageAccountKey -ResourceGroupName $storageRGName -AccountName $storageAccount).Value[0]
    #(ConvertTo-SecureString -String $saKey -AsPlainText -Force)
    $saKey = (ConvertTo-SecureString -String ((Get-AzStorageAccountKey -ResourceGroupName $storageRGName -AccountName $storageAccount).Value[0]) -AsPlainText -Force)
    $u = "Azure\" + $storageAccount
    Write-Host "Storage Account user: $u"
    Write-Host "Storage Account key: $saKey"

    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $u, $saKey
    $root = "\\" + $storageAccount + "." + $storageShareDomain + "\" + $storageShareName
    Write-Host "File share: $root"
    
    $mntName = "$storageAccount$storageShareName"
    New-PSDrive -Name $mntName -PSProvider FileSystem -Root $root -Credential $cred

    # Set Perms
    $path = $mntName + ":"
    Write-Host "-===== NTFS PERMS BEFORE CONFIG =====-"
    $acl = Get-Acl $path
    $acl.Access | Format-Table -AutoSize

    #Remove existing permissions
    $acl.Access | %{$acl.RemoveAccessRule($_)} | Out-Null
    
    # Config CREATOR OWNER
    $id = 'CREATOR OWNER'
    $perms = 'Modify'
    $inherit = 'ContainerInherit, ObjectInherit'
    $propagation = 'None'

    Write-Host "Setting share permissions for $id"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, $perms, $inherit, $propagation, 'Allow')
    $acl.SetAccessRule($AccessRule)

    # Config ADMIN PERMS
    $id = $adDomain + '\' + $ntfsAdmins
    $perms = 'FullControl'
    $inherit = 'ContainerInherit, ObjectInherit'
    $propagation = 'None'

    Write-Host "Setting share permissions for $id"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, $perms, $inherit, $propagation, 'Allow')
    $acl.SetAccessRule($AccessRule)
    

    # Config User Perms
    $id = $adDomain + '\' + $ntfsUsers
    $perms = 'Modify'
    $inherit = 'None'
    $propagation = 'None'

    Write-Host "Setting share permissions for $id"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, $perms, $inherit, $propagation, 'Allow')
    $acl.SetAccessRule($AccessRule)

    # Apply ACL
    $acl | Set-Acl -Path $path

    Write-Host "-===== NTFS PERMS AFTER CONFIG =====-"
    (Get-Acl -Path $path).Access | Format-Table -AutoSize

    # Unmount
    Remove-PSDrive -Name $mntName

}

