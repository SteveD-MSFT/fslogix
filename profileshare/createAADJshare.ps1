Install-Module -Name Az -Force
Install-Module -Name AzureAD -Force

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

    # Config Azure AD Service principal

    $ApiVersion = '2021-04-01'

    $Uri = ('https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}?api-version={3}' -f $sub, $storageRGName, $storageAccount, $ApiVersion);
    
    $json = 
       @{properties=@{azureFilesIdentityBasedAuthentication=@{directoryServiceOptions="AADKERB"}}};
    $json = $json | ConvertTo-Json -Depth 99
    
    $token = $(Get-AzAccessToken).Token
    $headers = @{ Authorization="Bearer $token" }
    
    try {
        Invoke-RestMethod -Uri $Uri -ContentType 'application/json' -Method PATCH -Headers $Headers -Body $json;
    } catch {
        Write-Host $_.Exception.ToString()
        Write-Error -Message "Caught exception setting Storage Account directoryServiceOptions=AADKERB: $_" -ErrorAction Stop
    }
    
    #Generate kerb storage account key
    New-AzStorageAccountKey -Name $storageRGName -Name $storageAccount -KeyName kerb1 -ErrorAction Stop
    
    $kerbKey1 = Get-AzStorageAccountKey -Name $storageRGName -Name $storageAccount -ListKerbKey | Where-Object { $_.KeyName -like "kerb1" }
    $aadPasswordBuffer = [System.Linq.Enumerable]::Take([System.Convert]::FromBase64String($kerbKey1.Value), 32);
    $password = "kk:" + [System.Convert]::ToBase64String($aadPasswordBuffer);
    
    Connect-AzureAD
    $azureAdTenantDetail = Get-AzureADTenantDetail;
    $azureAdTenantId = $azureAdTenantDetail.ObjectId
    $azureAdPrimaryDomain = ($azureAdTenantDetail.VerifiedDomains | Where-Object {$_._Default -eq $true}).Name
    
    $servicePrincipalNames = New-Object string[] 3
    $servicePrincipalNames[0] = 'HTTP/{0}.file.core.windows.net' -f $storageAccount
    $servicePrincipalNames[1] = 'CIFS/{0}.file.core.windows.net' -f $storageAccount
    $servicePrincipalNames[2] = 'HOST/{0}.file.core.windows.net' -f $storageAccount
    
    $application = New-AzureADApplication -DisplayName $storageAccount -IdentifierUris $servicePrincipalNames -GroupMembershipClaims "All";
    
    $servicePrincipal = New-AzureADServicePrincipal -AccountEnabled $true -AppId $application.AppId -ServicePrincipalType "Application";
    
    $Token = ([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken']).AccessToken
    $apiVersion = '1.6'
    $Uri = ('https://graph.windows.net/{0}/{1}/{2}?api-version={3}' -f $azureAdPrimaryDomain, 'servicePrincipals', $servicePrincipal.ObjectId, $apiVersion)
$json = @'
{
    "passwordCredentials": [
    {
    "customKeyIdentifier": null,
    "endDate": "<STORAGEACCOUNTENDDATE>",
    "value": "<STORAGEACCOUNTPASSWORD>",
    "startDate": "<STORAGEACCOUNTSTARTDATE>"
    }]
}
'@
    $now = [DateTime]::UtcNow
    $json = $json -replace "<STORAGEACCOUNTSTARTDATE>", $now.AddDays(-1).ToString("s")
      $json = $json -replace "<STORAGEACCOUNTENDDATE>", $now.AddMonths(12).ToString("s")
    $json = $json -replace "<STORAGEACCOUNTPASSWORD>", $password
    $Headers = @{'authorization' = "Bearer $($Token)"}
    try {
      Invoke-RestMethod -Uri $Uri -ContentType 'application/json' -Method Patch -Headers $Headers -Body $json 
      Write-Host "Success: Password is set for $storageAccount"
    } catch {
      Write-Host $_.Exception.ToString()
      Write-Host "StatusCode: " $_.Exception.Response.StatusCode.value
      Write-Host "StatusDescription: " $_.Exception.Response.StatusDescription
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

    

}

