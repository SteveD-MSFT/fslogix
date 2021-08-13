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
    Connect-AzAccount -Tenant $tenantID -Subscription $subID
}

# Iterate over shares and configure
foreach ($share in $shares) {

    #File Share
    $storageAccount           = $share.storageAccountName
    $storagelocation          = $share.location
    $storageRGName            = $share.rgName
    $storageSKU               = $share.skuName
    $storageShareName         = $share.shareName
    $smbElevatedContributor   = $share.smbElevatedContributor
    $smbContributor           = $share.smbContributor #TODO
    $ntfsUsers                = $share.$ntfsUsers

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
    New-AzRoleAssignment -objectID $id -RoleDefinitionName "Storage File Data SMB Share Elevated Contributor" -Scope $scope

    #NTFS Perms

    # Mount share
    $saKey = (Get-AzStorageAccountKey -ResourceGroupName $storageRGName -AccountName $storageAccount)| Where-Object {$_.KeyName -eq "key1"}
    $u = "Azure\" + $storageAccount
    $p = ConvertTo-SecureString -String $saKey -AsPlainText -Force
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $u, $p
    $root = "\\" + $storageAccount + "\" + $storageShareName
    New-PSDrive -Name "P" -PSProvider FileSystem -Root $root -Credential $cred

    # Set Perms
    Write-Debug "-===== NTFS PERMS BEFORE CONFIG =====-"
    Write-Debug (Get-Acl -Path $dir).Access | Format-Table -AutoSize
    


    Write-Debug "-===== NTFS PERMS AFTER CONFIG =====-"
    Write-Debug (Get-Acl -Path $dir).Access | Format-Table -AutoSize

    # Unmount
    Remove-PSDrive -Name "P"
}