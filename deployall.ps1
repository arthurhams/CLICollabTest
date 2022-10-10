cls
#region actions

$installAZModules = $false
$installFunctionsCore = $false
$connectSubscription = $false
$setAZContext = $false


$createResourceGroup = $true
$createStorageWithStaticWeb = $true
$createAppInsights = $true
$createFrontDoor  = $true
$createSignalR = $true
$createAppConfig = $true
$createServiceBus = $true
$createDNS = $true
$createStorageContainer  = $true
$createStorageTable  = $true
$createKeyVault = $true
$createFunctionAppInstance = $true
$createLocalFunction = $true
$publishFunction = $true
$createAPIMInstance = $true
$updateAndUploadFiles = $true

#B2C
$createADB2CTenant=$false

$createMultiContainerWebApp = $false
$createPostgressDB = $false
#endregion

$iteration = 30

#region variables
$subscriptionname = "Internal Subscription ArHallen" # to deploy into
$subscriptionid = "ce8f0ca1-212c-4572-9e98-ef56aaf20013"
$tenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"

$prefix = "spapwrshll"

$resourcegroupname = $prefix + "rg" + $iteration # to deploy into
$location = "westeurope" # to deploy into
$locationARM = "West Europe"

$loganalyticsname = $prefix + "la" + $iteration 
$appinsightsname = $prefix + "ai" + $iteration 

$hostingPlanName = $prefix + "asp" + $iteration
$functionappname = $prefix + "functionapp" + $iteration
$functionstorageaccountName = $prefix + "functionsa" + $iteration
$allowedOrigins = "" # will be set after static web creation
$functionname = $prefix + "functions"
$keyvaultname = $prefix + "kv" + $iteration # to deploy into

$storageaccountname = $prefix + "storage" + $iteration #without .blob.core.windows.net -> to replace {storageaccountname} in pagelayout, you will be asked to override if exists. https://{storageaccountname}.blob.core.windows.net/{containername}/
$containername = '$web' # to replace {containername} in pagelayout, error will be generated if already exists, no problem
$tableName = $prefix + "table" + $iteration

#DNS
$dnsresourcegroupname = "azuredemowebapp"
$baseurl = "azuredemowebapp.com"
$weburl = $prefix + "web" + $iteration

$frontDoorName = $prefix + "fd"

$frontendname = $prefix + "fdfrontend" + $iteration
$originname = $prefix + "fdorigin" + $iteration
$origingroupname = $prefix + "fdorigingroup" + $iteration
$routingroutename = $prefix + "fdroutingroute" + $iteration
$customdomainname = $weburl + "." + $baseurl 

$signalRName = $prefix + "signalr"  + $iteration
$appConfigName = $prefix + "appconfig"  + $iteration
$serviceBusName = $prefix + "sb"  + $iteration
$serviceBusQueueName = $prefix + "queue"  + $iteration

$apiminstancename = $prefix + "apim" + $iteration
$Organization = "spaorg" 
$AdminEmail  = "arhallen@microsoft.com"

$multiContainerWebAppSPA = $prefix + "mcasp" + $iteration
$multiContainerWebApp = $prefix + "mcapp" + $iteration

$postgreservername = $prefix + "pgserver" + $iteration
$postgresdbname = $prefix + "pgdb" + $iteration

$adb2ctenantname = $prefix + "b2c" + $iteration


#endregion 

$currentdirectory = "C:\Users\arhallen\Source\Repos\azuredemowebapp\azuredemowebapp-powershelldeploy" #"C:\Users\arhallen\Source\Repos\SPAPpowershell" #"C:\Users\arhallen\OneDrive\OneDrive - Microsoft\NS\" #eg c:\somefolder\somesubfolder
Set-Location $currentdirectory

if ($true)
{
 . .\Functions.ps1
 Testfunction1 -Name Arthur

}

if ( $installAZModules) { 

    Write-Host -------------I N S T A L L -  A Z  M o d u l e ------------
    Install-Module -Name Az -AllowClobber -Scope CurrentUser
    Install-Module -Name AzTable -Force
    Install-Module -Name Az.FrontDoor -AllowClobber  -Force

    Install-Module  Microsoft.Grap

    Write-Host -------------G E T - A Z M o d u l e------------
    Write-Host Get AZ Module
    Get-InstalledModule -Name "Az"
    }

if ( $installFunctionsCore) { 

    Write-Host -------------I N S T A L L  -  A Z U R E -  F U N C T I O N S  - C O R E ------------
    npm install -g unzipper
    npm update
    npm i -g glob
    npm i -g rimraf
    npm i -g progress
    npm i -g https-proxy-agent
    npm install -g azure-functions-core-tools@4
}

#update node here: https://nodejs.org/en/download/current/

if ( $connectSubscription) { 
Write-Host -------------C O N N E C T------------
    Connect-AzAccount -Subscription $subscriptionname
}

if ( $setAZContext) { 

    Write-Host -------------L O G I N ------------
    #az login --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --use-device-code

    $context = Get-AzSubscription -SubscriptionId $subscriptionid -TenantId $tenantId
    Set-AzContext $context
}

if ( $createResourceGroup) { 

    Write-Host -------------R E S O U R C E  -  G R O U P------------

    #create res group if not exists
    Write-Host Create Resource Group
    New-AzResourceGroup -Name $resourcegroupname -Location $location

}
if ( $createAppInsights) { 

    Write-Host ------------- A P P   I N S I G H T S ------------
    
    $AzOperationalInsightsWorkspace =  New-AzOperationalInsightsWorkspace -Location $location -Name $loganalyticsname -ResourceGroupName $resourcegroupname

    New-AzApplicationInsights -ResourceGroupName $resourcegroupname -Name $appinsightsname -location $location -WorkspaceResourceId $AzOperationalInsightsWorkspace.ResourceId
}
$AzApplicationInsights = Get-AzApplicationInsights  -ResourceGroupName $resourcegroupname -Name $appinsightsname 
#$AzApplicationInsightsApiKey = Get-AzApplicationInsightsApiKey -ResourceGroupName $resourcegroupname -Name $appinsightsname

if ( $createStorageWithStaticWeb) { 
    Write-Host -------------B L O B  - S T O R A G E /  S P A ------------


    # Deploy storage account
    #if (!Test-AzureName -Storage $storageaccountname)
    #{
    Write-Host Create Storage Account

    New-AzStorageAccount -ResourceGroupName $resourcegroupname `
      -Name $storageaccountname -Location $location `
      -SkuName Standard_LRS  -Kind StorageV2 
    # }
    Write-Host Get Storage Account
    $StorageAccount = Get-AzStorageAccount -Name $storageaccountname -ResourceGroupName $resourcegroupname

        Write-Host Create Enable-AzStorageStaticWebsite
    $staticwebsite = Enable-AzStorageStaticWebsite -Context $StorageAccount.Context -IndexDocument index.html -ErrorDocument404Path error.html

    Write-Host Set CORS rule
    $CorsRules = (@{
        AllowedOrigins=@("*");
        MaxAgeInSeconds=30;
        AllowedMethods=@("Get","Post", "Connect")}
        )
    Set-AzStorageCORSRule -ServiceType Blob -CorsRules $CorsRules -Context $StorageAccount.Context

    # change files -> 
    Write-Host Changing Files
    Set-Location $currentdirectory

    # Add files
    Write-Host Copy files to Azure

    $contentType = @{"ContentType"="text/html"}
    Set-AzStorageBlobContent –File .\site\index.html –Blob index.html -Properties $contentType -Context $StorageAccount.Context -Container $containername

    Write-Output "Website can be found here: "
    Write-Output $storageAccount.PrimaryEndpoints.Web

    #https://spapwrshllstorage.z6.web.core.windows.net/


}
$StorageAccount = Get-AzStorageAccount -Name $storageaccountname -ResourceGroupName $resourcegroupname

if ( $createFrontDoor) { 
    Write-Host -------------F R O N T -  D O O R  ------------
    
    $fdprofile = New-AzFrontDoorCdnProfile `
    -ResourceGroupName $resourcegroupname `
    -Name $frontDoorName `
    -SkuName Standard_AzureFrontDoor `
    -Location Global

#Create the endpoint

$FDendpoint = New-AzFrontDoorCdnEndpoint `
    -EndpointName $frontendname `
    -ProfileName $frontDoorName `
    -ResourceGroupName $resourcegroupname `
    -Location Global

# Create health probe settings

$HealthProbeSetting = New-AzFrontDoorCdnOriginGroupHealthProbeSettingObject `
    -ProbeIntervalInSecond 60 `
    -ProbePath "/" `
    -ProbeRequestType GET `
    -ProbeProtocol Http

# Create load balancing settings

$LoadBalancingSetting = New-AzFrontDoorCdnOriginGroupLoadBalancingSettingObject `
    -AdditionalLatencyInMillisecond 50 `
    -SampleSize 4 `
    -SuccessfulSamplesRequired 3

# Create origin group

$originpool = New-AzFrontDoorCdnOriginGroup `
    -OriginGroupName $origingroupname `
    -ProfileName $frontDoorName `
    -ResourceGroupName $resourcegroupname `
    -HealthProbeSetting $HealthProbeSetting `
    -LoadBalancingSetting $LoadBalancingSetting

    $origin1 = New-AzFrontDoorCdnOrigin `
    -OriginGroupName $origingroupname `
    -OriginName $originname `
    -ProfileName $frontDoorName `
    -ResourceGroupName $resourcegroupname `
    -HostName  $storageAccount.PrimaryEndpoints.Web.Replace("https:", "").Replace("/", "") `
    -OriginHostHeader $storageAccount.PrimaryEndpoints.Web.Replace("https:", "").Replace("/", "") `
    -HttpPort 80 `
    -HttpsPort 443 `
    -Priority 1 `
    -Weight 1000

    $Route = New-AzFrontDoorCdnRoute `
    -EndpointName $frontendname `
    -Name $routingroutename `
    -ProfileName $frontDoorName `
    -ResourceGroupName $resourcegroupname `
    -ForwardingProtocol MatchRequest `
    -HttpsRedirect Enabled `
    -LinkToDefaultDomain Enabled `
    -OriginGroupId $originpool.Id `
    -SupportedProtocol Http,Https 
    #-CustomDomainName  $customdomainname



}


$AzureFrontDoor = Get-AzFrontDoorCdnProfile -Name $frontDoorName -ResourceGroupName $resourcegroupname 
$FDendpoint = Get-AzFrontDoorCdnEndpoint -EndpointName $frontendname -ProfileName $frontDoorName -ResourceGroupName $resourcegroupname 


if ( $createDNS) { 
    Write-Host -------------D N S   ------------
    #New-AzDnsZone -Name $baseurl  -ResourceGroupName $resourcegroupname
    $DnsZone = Get-AzDnsZone -Name $baseurl  -ResourceGroupName $dnsresourcegroupname
        
    
    #$RecordSet = New-AzDnsRecordSet -Name $weburl -RecordType A -ResourceGroupName $dnsresourcegroupname -TTL 3600 -ZoneName $baseurl  -TargetResourceId $FDendpoint.Id # $AzureFrontDoor.Id #-DnsRecords $Records
        
               
        $Records = @()
        $Records += New-AzDnsRecordConfig -Cname $FDendpoint.HostName
        $RecordSet = New-AzDnsRecordSet -Name $weburl -RecordType CNAME -ResourceGroupName $dnsresourcegroupname -TTL 3600 -ZoneName $baseurl  -DnsRecords $Records


        $AzFrontDoorCdnCustomDomain = New-AzFrontDoorCdnCustomDomain -AzureDnsZoneId $DnsZone.Name `
        -CustomDomainName $weburl `
        -ProfileName $frontDoorName `
        -ResourceGroupName $resourcegroupname `
        -HostName $customdomainname
     
        $Records = @()
        $Records += New-AzDnsRecordConfig -Value $AzFrontDoorCdnCustomDomain.ValidationPropertyValidationToken 
        $dnsauth = "_dnsauth." + $weburl
        $RecordSet = New-AzDnsRecordSet -Name $dnsauth -RecordType TXT -ResourceGroupName $dnsresourcegroupname -TTL 3600 -ZoneName $baseurl -DnsRecords $Records


        $FDCdnRoute = Update-AzFrontDoorCdnRoute `
        -EndpointName $frontendname `
        -Name $routingroutename `
        -ProfileName $frontDoorName `
        -ResourceGroupName $resourcegroupname `
        -CustomDomain @{Id=$AzFrontDoorCdnCustomDomain.Id }

       # Enable-AzFrontDoorCustomDomainHttps `
       # -ResourceGroupName $resourcegroupname `
       # -FrontDoorName $frontDoorName `
       # -FrontendEndpointName $frontendname
  
      
}

if ( $createStorageContainer) { 
Write-Host -------------B L O B -  S T O R A G E /  C O N T A I N E R ------------
    
   # if (!Test-AzureName -Storage $storageaccountname)
    {
        Write-Host Create Storage 
        $StorageAccount = Get-AzStorageAccount -Name $storageaccountname -ResourceGroupName $resourcegroupname
        $storageContainer = New-AzStorageContainer -Name $containername -Permission Blob -Context $StorageAccount.Context
    }
    Write-Host Get Storage 
    $storageContainer = Get-AzStorageContainer -Name $containername -Context $StorageAccount.Context

}

if ( $createStorageTable) { 
    Write-Host -------------T A B L E - S T O R A G E ------------

#    if (!Test-AzureName -Storage $storageaccountname)
#    {
        Write-Host Create Storage 
        $StorageAccount = Get-AzStorageAccount -Name $storageaccountname -ResourceGroupName $resourcegroupname
        New-AzStorageTable –Name $tableName –Context $StorageAccount.Context
#    }
    Write-Host Get Cloud Table
    $cloudTable = (Get-AzStorageTable –Name $tableName –Context $StorageAccount.Context).CloudTable
    
    $partitionKey1 = "partition1"

    # add row
    Add-AzTableRow `
        -table $cloudTable `
        -partitionKey $partitionKey1 `
        -rowKey ("CA") -property @{"username"="Chris";"userid"=1}


}

Write-Host "Get table storage connection string"
$saKey = (Get-AzStorageAccountKey -ResourceGroupName $resourcegroupname -Name $storageaccountname)[0].Value
$tableconnectionstring = 'DefaultEndpointsProtocol=https;AccountName=' + $storageaccountname + ';AccountKey=' + $saKey + ';EndpointSuffix=core.windows.net' 

$fullfeaddress = "https://" + $FDendpoint.HostName
$fullcustomdomain = "https://" + $weburl + "." + $baseurl
$apimaddress = "https://" + $apiminstancename + ".azure-api.net"
$allowedOrigins = $storageAccount.PrimaryEndpoints.Web.Substring(0, $storageAccount.PrimaryEndpoints.Web.Length - 1), $fullfeaddress, $fullcustomdomain, $apimaddress


if ( $createFunctionAppInstance) { 

    Write-Host -------------C R A Z U R E -   F U N C T I O N ------------

    #New-AzAppServicePlan -ResourceGroupName $resourcegroupname -Name $functionappname -Location $location  -Tier "Dynamic"

        Write-Host Create Function Storage Account

    New-AzStorageAccount -ResourceGroupName $resourcegroupname `
      -Name $functionstorageaccountName -Location $location `
      -SkuName Standard_LRS  -Kind StorageV2


    New-AzFunctionApp -Name $functionappname `
                  -ResourceGroupName $resourcegroupname `
                  -Location $location `
                  -StorageAccountName $functionstorageaccountName `
                  -Runtime DotNet -FunctionsVersion 4 -OSType Windows -RuntimeVersion 6 `
                  -ApplicationInsightsKey $AzApplicationInsights.InstrumentationKey `
                  -ApplicationInsightsName $AzApplicationInsights.Name

      Write-Host "Set CORS in function app"

 
    foreach ($item in $allowedOrigins) 
    {
        Write-Host "Check if allowedorigin '$item' is already set"
        $missesOrigin = az functionapp cors show --name "$functionappname" --resource-group $resourcegroupname #--query "contains(to_string(length(allowedOrigins&#91;?contains(@, '$item')])),'0')"
        $hascors = 0;
        foreach ($corsitem in $missesOrigin) 
        {
            if ($corsitem.Contains($item))
            {
                $hascors = 1;
                break;
            }
            
        }

        if ($hascors -eq 0) 
        {
            Write-Host "Add allowedorigin '$item'"
            az functionapp cors add -n "$functionappname" --allowed-origins $item --resource-group $resourcegroupname 
        }
        else {
            Write-Host "Allowedorigin '$item' already set"
        }
    }
    
    Write-Host "Create managed identity"
    Set-AzWebApp -AssignIdentity $true -Name $functionappname -ResourceGroupName $resourcegroupname 


}

if ( $createAppConfig) { 
    #new signalR
#module Az.SignalR 
Write-Host -------------C R E A T E  -   A P P C O N F I G ------------
$AzAppConfig = New-AzAppConfigurationStore -ResourceGroupName $resourcegroupname -Name $appConfigName -Location $location -Sku standard #free
#$AzSignalR.Cors = 
}
$AzAppConfigurationStoreKey = Get-AzAppConfigurationStoreKey -ResourceGroupName $resourcegroupname -Name $appConfigName
$AzAppConfigurationStoreConnectionstring = $AzAppConfigurationStoreKey[0].ConnectionString 

if ( $createSignalR) { 
    #new signalR
#module Az.SignalR 
Write-Host -------------C R E A T E  -   S I G N A L R ------------
$AzSignalR = New-AzSignalR -ResourceGroupName $resourcegroupname -Name $signalRName -Location $location -Sku Free_F1 -UnitCount 1 -AllowedOrigin $allowedOrigins
#$AzSignalR.Cors = 
}

#$AzureSignalR = Get-AzSignalR -ResourceGroupName $resourcegroupname -Name $signalRName
$AzureSignalRKey = Get-AzSignalRKey -ResourceGroupName $resourcegroupname -Name $signalRName
$signalrconnectionstring = $AzureSignalRKey.PrimaryConnectionString;

if ( $createServiceBus) { 
    Write-Host -------------C R E A T E  -   S E R V I C E  B U S ------------
#new servicebus
# module Az.ServiceBus
New-AzServiceBusNamespace -ResourceGroupName $resourcegroupname -Name $serviceBusName -Location $location -SkuName "Standard" #-Tag @{Tag1="Tag1Value"}
New-AzServiceBusQueue -ResourceGroup $resourcegroupname -NamespaceName $serviceBusName -QueueName $serviceBusQueueName -EnablePartitioning $True
}

#Write-Host "WARNING - TODO: FIX!!! Get servicebus connectionstring "
$AzureServiceBusKey = Get-AzServiceBusKey -Name "RootManageSharedAccessKey" -ResourceGroupName $resourcegroupname -Namespace $serviceBusName
$servicebusconnectionstring = $AzureServiceBusKey.PrimaryConnectionString
#new function app

#new function to receive http request to put message in SB

#new function to get message from SB into signalR



if ( $createKeyVault) { 
    Write-Host -------------C R E A T E  -   K E Y V A U L T------------

    New-AzKeyVault -VaultName $keyvaultname -ResourceGroupName $resourcegroupname -Location $locationARM

    $TableSecret = ConvertTo-SecureString -String $tableconnectionstring -AsPlainText -Force
    $Tablesecreturi = Set-AzKeyVaultSecret -VaultName $keyvaultname -Name 'TableConnectionString' -SecretValue $TableSecret

    $SignalRSecret = ConvertTo-SecureString -String $signalrconnectionstring -AsPlainText -Force
    $SignalRsecreturi = Set-AzKeyVaultSecret -VaultName $keyvaultname -Name 'AzureSignalRConnectionString' -SecretValue $SignalRSecret

    $ServiceBusSecret = ConvertTo-SecureString -String $servicebusconnectionstring -AsPlainText -Force
    $ServiceBussecreturi = Set-AzKeyVaultSecret -VaultName $keyvaultname -Name 'ServiceBusConnectionString' -SecretValue $ServiceBusSecret

    $AppConfigSecret = ConvertTo-SecureString -String $AzAppConfigurationStoreConnectionstring -AsPlainText -Force
    $AppConfigecreturi = Set-AzKeyVaultSecret -VaultName $keyvaultname -Name 'AppConfigConnectionString' -SecretValue $AppConfigSecret

    
    $objectid = (Get-AzWebApp -Name $functionappname).Identity.PrincipalId

     Set-AzKeyVaultAccessPolicy -VaultName $keyvaultname -ObjectId $objectid -PermissionsToSecrets Get
     
    write-host "Reference Keyvault value in App Settings"
    $webapp=Get-AzWebApp -ResourceGroupName $resourceGroupName  -Name $functionappname
    $appSettings=$webapp.SiteConfig.AppSettings
    $newAppSettings = @{}
    ForEach ($item in $appSettings) {
        $newAppSettings[$item.Name] = $item.Value
    }
    
    $newAppSettings['TableConnectionString'] = ("@Microsoft.KeyVault(SecretUri={0})" -f $Tablesecreturi.id) 
    $newAppSettings['AzureSignalRConnectionString'] = ("@Microsoft.KeyVault(SecretUri={0})" -f $SignalRsecreturi.id) 
    $newAppSettings['ServiceBusConnectionString'] = ("@Microsoft.KeyVault(SecretUri={0})" -f $ServiceBussecreturi.id) 
    $newAppSettings['AppConfigConnectionString'] = ("@Microsoft.KeyVault(SecretUri={0})" -f $AppConfigecreturi.id) 

    $newAppSettings['SignalRHubName'] = $signalRName 
    $newAppSettings['SBQueueName'] = $serviceBusQueueName 

    Set-AzWebApp -ResourceGroupName $resourceGroupName -Name $functionappname  -AppSettings $newAppSettings
}
 if ( $createLocalFunction) { 

    Write-Host -------------C R E A T E   L O C A L   A Z U R E -   F U N C T I O N ------------
    if (Test-Path $functionappname -PathType Any) {
        Remove-Item -Path $functionappname -Recurse
        }
    #create local function
    func init $functionappname --dotnet --worker-runtime csharp #--csx  # 
    #below fails with .net core 6
    #func new --name $functionname --template "HTTP trigger" --csharp --force

    Remove-Item $functionappname\*.csproj
    Copy-Item "functions_template\*.*"  $functionappname -Recurse
    Set-Location $functionappname
    $newname = $functionappname + ".cs"
    Rename-Item "spapowershellfunctions.cs" $newname 
    $newname = $functionappname + ".csproj"
    Rename-Item "spapowershellfunctions.csproj" $newname 

        #fill function settings for local testing

        Remove-Item local.settings.json
        Rename-Item local.settings_template.json local.settings.json 
    
        (Get-Content -Path 'local.settings.json') |
    ForEach-Object {$_ -Replace '{ServiceBusConnectionString}', $servicebusconnectionstring} |
    ForEach-Object {$_ -Replace '{SignalRConnectionString}', $signalrconnectionstring} |
    ForEach-Object {$_ -Replace '{AppConfigConnectionString}', $AzAppConfigurationStoreConnectionstring} |
    ForEach-Object {$_ -Replace '{SignalRHubName}', $signalRName} |
    ForEach-Object {$_ -Replace '{SBQueueName}', $serviceBusQueueName} |
       Set-Content -Path 'local.settings.json'

    #func start --build
    #Set-Location ..

}
if ( $publishFunction) { 

    Write-Host -------------P U B L I S H  -   F U N C T I O N ------------
    if (Test-Path $functionappname -PathType Any) {
        Set-Location $functionappname
    }
    #publish to Azure
    func azure functionapp publish $functionappname --csharp
    cd..


}

if($true) #$oldcodetogetfunctionurlincludingcode
{
    Write-Host -------------G E T  -  A Z U R E  -  F U N C T I O N ------------
    $functionApp = Get-AzWebApp -Name $functionappname -ResourceGroup $resourcegroupname #-Slot "Production"

    #$functionSecrets = Invoke-AzResourceAction -ResourceId ("{0}/functions/{1}" -f $functionApp.Id, $functionname) -Action "listkeys" -ApiVersion "2019-08-01" -Force
    $uri = "https://management.azure.com/" + $functionApp.Id + "/" + $functionname + "/host/default/listKeys?api-version=2018-11-01"
    $uri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourcegroupname/providers/Microsoft.Web/sites/$functionappname/host/default/listKeys?api-version=2018-11-01"
    $functionkeylist = az rest --method post --uri $uri
    $keylistobject = $functionkeylist | ConvertFrom-Json
    $functionSecret = $keylistobject.functionKeys.default

    #$functionSecret = $functionSecretS.default

    $fullfunctionurl = ("https://{0}.azurewebsites.net/api/{1}?code={2}" -f $functionappname, $functionname,$functionSecret)
    write-host "function can be called like this:" 
    write-host $fullfunctionurl
 
}


if ( $createAPIMInstance) { 

Write-Host -------------A P I -  M A N A G E M E N T------------
#import-Module Az.ApiManagement
New-AzApiManagement -ResourceGroupName $resourcegroupname -Location $locationARM -Name $apiminstancename -Organization $Organization -AdminEmail $AdminEmail -Sku "Consumption"

$apiminstance = Get-AzApiManagement -ResourceGroupName $resourcegroupname -Name $apiminstancename
$ApiMgmtContext = New-AzApiManagementContext -ResourceGroupName $resourcegroupname -ServiceName $apiminstancename

$loggerid = $apiminstancename + "logger"
$AzApiManagementLogger = New-AzApiManagementLogger -LoggerId $loggerid -Context $ApiMgmtContext -InstrumentationKey $AzApplicationInsights.InstrumentationKey
New-AzApiManagementDiagnostic -Context $ApiMgmtContext -LoggerId $loggerid -DiagnosticId "applicationinsights"


$prop = @{
    alwaysLog = "allErrors"
    enableHttpCorrelationHeaders = $True
    loggerId = "/loggers/" + $AzApiManagementLogger.Id
    sampling = @{
        samplingType = "fixed"
        percentage = 50
          }
    }

$apiVersion = "2018-06-01-preview"
$resourceId = "/subscriptions/" + $subscriptionid + "/resourceGroups/" + $resourcegroupname + "/providers/Microsoft.ApiManagement/service/" + $apiminstancename + "/diagnostics/applicationinsights"

New-AzResource -ResourceId $resourceId -Properties $prop -ApiVersion $apiVersion -Force


$functionappkeyname = $functionappname + "-key"
New-AzApiManagementNamedValue -Context $ApiMgmtContext -NamedValueId $functionappkeyname  -Name $functionappkeyname  -Value $functionSecret 

$credential = New-AzApiManagementBackendCredential -AuthorizationHeaderScheme basic -Header @{"x-functions-key" = @("{{$functionappkeyname}}")}  

$functionurl = "https://" + $functionapp.DefaultHostName + "/api";
$backend = New-AzApiManagementBackend -Context  $ApiMgmtContext -BackendId $functionappname -Url $functionurl -Protocol http -Title $functionappname  -Credential $credential -Description $functionappname 

$backendpolicy ="<policies> <inbound><base />`
<cors allow-credentials=" + '"true"' + ">`
<allowed-origins>`
    <origin>http://localhost:44343/</origin>`
    <origin>https://" + $customdomainname + "/</origin>`
</allowed-origins>`
<allowed-methods>`
    <method>GET</method>`
    <method>POST</method>`
</allowed-methods>`
</cors>`
<set-backend-service backend-id=" + '"' +  $functionappname + '"' +  " /></inbound>`
    <backend><base /></backend>`
    <outbound><base /></outbound>`
    <on-error><base /></on-error>`
</policies>"

#New-AzApiManagementApi -Context $ApiMgmtContext -Name "ContactAPI" -ApiId "ContactAPI" -Protocols @("http", "https") # -Path "/" -ServiceUrl ""#$fullfunctionurl

$PropertiesObject = @{
    "name" = $functionappname
    "serviceUrl" =  $null
    "path" = "/"
    "protocols" = @("https")
    "subscriptionRequired" = $false
}
$resourcename = $apiminstancename + "/" + $functionappname
New-AzResource -PropertyObject $PropertiesObject -ResourceGroupName $resourcegroupname -ResourceType Microsoft.ApiManagement/service/apis -ResourceName $resourcename -ApiVersion 2018-01-01 -Force

#$resourcename = $apiminstancename + "/httplistener" 
#New-AzResource -PropertyObject $PropertiesObject -ResourceGroupName $resourcegroupname -ResourceType Microsoft.ApiManagement/service/apis -ResourceName $resourcename -ApiVersion 2018-01-01 -Force


New-AzApiManagementOperation -Context $ApiMgmtContext -ApiId $functionappname -OperationId $functionname -UrlTemplate $functionname -Name $functionname -Method "POST" -Description "Use this operation to get resource"

New-AzApiManagementOperation -Context $ApiMgmtContext -ApiId $functionappname -OperationId "httplistener" -UrlTemplate "httplistener" -Name "httplistener" -Method "GET" -Description "GET to httplistener"
New-AzApiManagementOperation -Context $ApiMgmtContext -ApiId $functionappname -OperationId "httplistener" -UrlTemplate "httplistener" -Name "httplistener" -Method "POST" -Description "POST to httplistener"

New-AzApiManagementOperation -Context $ApiMgmtContext -ApiId $functionappname -OperationId "status-0123456789abcdef" -UrlTemplate "status-0123456789abcdef" -Name "healthcheck" -Method "GET" -Description "GET to /status-0123456789abcdef"

Set-AzApiManagementPolicy -Context $ApiMgmtContext -ApiId $functionappname -Policy $backendpolicy 

$fullfunctionurl = $apiminstance.RuntimeUrl + "/httplistener"
write-host "function can be called like this:" 
write-host $fullfunctionurl

#https://medium.com/the-new-control-plane/api-certificate-authentication-for-azure-ad-b2c-c3bf6a959855

}

$apiminstance = Get-AzApiManagement -ResourceGroupName $resourcegroupname -Name $apiminstancename
$fullfunctionurl = $apiminstance.RuntimeUrl + "/httplistener"



if ( $updateAndUploadFiles) {
  

    Write-Host -------------C R E A T E   -  F I L E S ------------
    
    (Get-Content -Path '.\site\js\scripts_template.js') |
    ForEach-Object {$_ -Replace '{functionurl}', $fullfunctionurl} |
       Set-Content -Path '.\site\js\scripts.js'

    (Get-Content -Path '.\site\index_template.html') |
    ForEach-Object {$_ -Replace '{functionurl}', $fullfunctionurl} |
    ForEach-Object {$_ -Replace '{appinsightsconnectionstring}', $AzApplicationInsights.ConnectionString} |
       Set-Content -Path '.\site\index.html'


    Write-Host ------------- U P L O A D -  F I L E S ------------


    $files = Get-ChildItem .\site -force -recurse # | Where-Object {$_.mode -match "-a---"} # Filter for better fp 
    foreach ($file in $files)
    { 
        #fqName represents fully qualified name 
        $fqName = $file.FullName 
        $dirname = $file.FullName.Replace($currentdirectory, "")
        $dirname = $dirname.Replace($file.name, "")
        $dirname = $dirname.Replace("\site", "")
        $dirname = $dirname.Replace("\", "")
        if($dirname -ne "")
        {
            $dirname = $dirname + "/"
        }
        if ($file.Extension -eq ".publishsettings" -Or $file.name -match "_template")
        {
        }
        else
         
        {   switch ($file.Extension)
            {
              ".html" {$contentType = @{"ContentType"="text/html"}}
              ".css" {$contentType = @{"ContentType"="text/css"}}
              ".gif" {$contentType = @{"ContentType"="image/gif"}}
              ".png" {$contentType = @{"ContentType"="image/png"}}
              ".jpeg" {$contentType = @{"ContentType"="image/jpeg"}}
              ".jpg" {$contentType = @{"ContentType"="image/jpg"}}
              ".js" {$contentType = @{"ContentType"="application/x-javascript"}}
             }

        }

        #Write-Host Get Storage Account
        if (!$StorageAccount) 
        {
            $StorageAccount= Get-AzStorageAccount -Name $storageaccountname -ResourceGroupName $resourcegroupname
        }


        #Write-Host Get Storage container
        if (!$storageContainer) 
        {
            $storageContainer = Get-AzStorageContainer -Name $containername -Context $StorageAccount.Context
        }

      Write-Host "Uploading " $dir $file.Name  -ForegroundColor Green  
      $blobfilename = $dirname + $file.Name
      Set-AzStorageBlobContent -Blob $blobfilename -Properties $contentType  -File $fqName -Context $StorageAccount.Context -Container $storageContainer.CloudBlobContainer.Name -Force | Out-Null
   
   } 
} 



if($createMultiContainerWebApp){

 #create App Service Plan (virtual Server)
az appservice plan create --name multicontainerWPTestASP --resource-group $resourcegroupname --sku S1 --is-linux

#create Web App with multi-container support
az webapp create --resource-group $resourcegroupname --plan $multiContainerWebAppSPA --name $multiContainerWebApp --multicontainer-config-type compose --multicontainer-config-file docker-compose-wordpress.yml

#mapp custom domain
az webapp config hostname add --webapp-name $multiContainerWebApp --resource-group $resourcegroupname --hostname multicontainerWPTest.azuredemowebapp.com

#Enable App Service Storage for persistence
az webapp config appsettings set --resource-group $resourcegroupname --name $multiContainerWebApp --settings WEBSITES_ENABLE_APP_SERVICE_STORAGE=TRUE

#update web app with new compose
az webapp config container set --resource-group $resourcegroupname --name $multiContainerWebApp --multicontainer-config-type compose --multicontainer-config-file docker-compose-wordpress.yml

#use azure file share as storage 
#https://stackoverflow.com/questions/64287843/mount-azure-file-share-to-web-app-for-linux-containers-with-docker-compose
}

if($createPostgressDB){
#create postgreSQL Flexible Server
#https://docs.microsoft.com/en-us/cli/azure/postgres/flexible-server?view=azure-cli-latest#az-postgres-flexible-server-create
az postgres flexible-server create --location $location --resource-group $resourcegroupname `
  --name $postgreservername --admin-user multicontainerwp --admin-password testpgserver123! `
  --sku-name Standard_B2s --tier Burstable --public-access 46.21.160.66 --storage-size 128 `
  --tags "key=value" --version 13 

#create postgreSQL Database
az postgres db create -g $resourcegroupname -s $postgreservername -n $postgresdbname


#enable Postgres azure.extension on 
#https://docs.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-extensions

#az postgres flexible-server parameter list --resource-group multicontainerWPTest --server-name multicontainerwptestpgserver2
#az postgres flexible-server parameter show --name azure.extensions shared --resource-group multicontainerWPTest --server-name multicontainerwptestpgserver2

az postgres flexible-server parameter set --resource-group $resourcegroupname --server-name $postgreservername --name azure.extensions --value postgis_topology,postgis,postgis_raster

#OPTIONAL
# Create a container registry
#https://docs.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-quick-task
#az acr create --resource-group resourcegroupname --name multicontainerwotestacr --sku Basic
   
}
if($createADB2CTenant){
 . .\DeployB2CTenant.ps1
Initialize-B2CTenant -B2CTenantName $adb2ctenantname -ResourceGroupName $resourcegroupname -Location "Europe" -CountryCode "NL"


#protect using angular MSAL
#https://docs.microsoft.com/en-us/azure/architecture/guide/resilience/azure-ad-secure-single-page-application

}

Write-Host "TODO: Add function to send to service hub"
Write-Host "TODO: Add database"
Write-Host "TODO: Add function to send from service hub to sql"
Write-Host "TODO: Add powerapp to interact with database"
Write-Host "TODO: Add azure ad tenant"
Write-Host "TODO: Add static web with azure ad connected"
Write-Host "TODO: Add Event Grid to send from SQL to static app"
Write-Host "TODO: connect static app to signalr"
Write-Host "<--- D O N E --->" 
Write-Host "Check it out: " $customdomainname 
