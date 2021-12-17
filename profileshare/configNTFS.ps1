$resourceGroupName = "azure-eastus-rg"
$storageAccountName = "scdeusavdprofiles"

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

