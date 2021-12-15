#Get config info
$config = '..\run.config.default.json'
$jConfig = Get-Content $config | ConvertFrom-Json
$tenant = $jConfig.args.tenant
$sub = $jConfig.args.subscription
$shares = $jConfig.shares

Write-Debug "Tenant: $tenant"
Write-Debug "Resource Group: $rgName"

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
    Write-Debug "Container Storage: CREATING $storageAccount and $storageShareName in $storageRGName ($storagelocation)"

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
    #Constrain the scope to the target file share
    $scope = "/subscriptions/" + $sub + "/resourceGroups/" + $storageRGName + "/providers/Microsoft.Storage/storageAccounts/" + $storageAccount + "/fileServices/default/fileshares/" + $storageShareName
   
    #Elevated SMB Contributor
    $group = Get-AzAdGroup -searchstring $smbElevatedContributor
    $id = $group.Id

    #get current roles
    #$roles = Get-AzRoleAssignment -objectID $id
    
    $newRole = "Storage File Data SMB Share Elevated Contributor"
    #dirty
    New-AzRoleAssignment -objectID $id -RoleDefinitionName $newRole -Scope $scope -ErrorAction SilentlyContinue

    #SMB Contributor
    $group = Get-AzAdGroup -searchstring $smbContributor
    $id = $group.Id

    $newRole = "Storage File Data SMB Share Contributor" 
    New-AzRoleAssignment -objectID $id -RoleDefinitionName $newRole -Scope $scope -ErrorAction SilentlyContinue

    #NTFS Perms

    # Mount share
    #$saKey = (Get-AzStorageAccountKey -ResourceGroupName $storageRGName -AccountName $storageAccount).Value[0]
    #(ConvertTo-SecureString -String $saKey -AsPlainText -Force)
    $saKey = (ConvertTo-SecureString -String ((Get-AzStorageAccountKey -ResourceGroupName $storageRGName -AccountName $storageAccount).Value[0]) -AsPlainText -Force)
    $u = "Azure\" + $storageAccount
    Write-Debug "Storage Account user: $u"
    Write-Debug "Storage Account key: $saKey"

    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $u, $saKey
    #$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $u, (ConvertTo-SecureString -String $saKey -AsPlainText -Force)

    $root = "\\" + $storageAccount + "." + $storageShareDomain + "\" + $storageShareName
    Write-Debug "File share: $root"
    
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