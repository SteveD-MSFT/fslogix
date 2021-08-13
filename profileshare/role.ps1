#Get the name of the custom role
#$FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
#Constrain the scope to the target file share
$scope = "/subscriptions/09951193-852c-44f6-a720-ccb1f897d1bd/resourceGroups/azure-westus2-rg/providers/Microsoft.Storage/storageAccounts/scdavdwestus2/fileServices/default/fileshares/profiles"
#Assign the custom role to the target identity with the specified scope.
$group = Get-AzAdGroup -searchstring "WVD Admins"
$id = $group.Id
New-AzRoleAssignment -objectID $id -RoleDefinitionName "Storage File Data SMB Share Elevated Contributor" -Scope $scope