$smbElevatedContributor = 'WVD Admins'
$sub = '09951193-852c-44f6-a720-ccb1f897d1bd'
$storageRGName = 'azure-eastus-rg'
$storageAccount = 'scdavdeastus'
$storageShareName = 'profiles'

$scope = "/subscriptions/" + $sub + "/resourceGroups/" + $storageRGName + "/providers/Microsoft.Storage/storageAccounts/" + $storageAccount + "/fileServices/default/fileshares/" + $storageShareName
If (!(Get-AzContext)) {
    Write-Host "Please login to your Azure account"
    Connect-AzAccount -Tenant $tenant -Subscription $sub
}


    #Elevated SMB Contributor
    $group = Get-AzAdGroup -searchstring $smbElevatedContributor
    $id = $group.Id

    #get current roles
    $roles = Get-AzRoleAssignment -objectID $id -Scope $scope
    
   # Write-Host "Roles"
    #foreach ($role in $roles) {
    #    WRite-Host $role.RoleDefinitionName
    #}

    $newRole = "Storage File Data SMB Share Elevated Contributor"
    if ($roles.RoleDefinitionName -notmatch "$newRole") {
    #    New-AzRoleAssignment -objectID $id -RoleDefinitionName $newRole -Scope $scope
        Write-Host "Role found"
    }