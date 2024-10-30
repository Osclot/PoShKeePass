function ConvertTo-KeePassPSObject {
    <#
        .SYNOPSIS
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.
        .DESCRIPTION
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.

            It will get the Protected Strings from the database like, Title,UserName,Password,URL,Notes.

            It currently returns Most frequently used data about an entry and excludes extensive metadata such as-
            Foreground Color, Icon, ect.
        .EXAMPLE
            PS> ConvertTo-KeePassPsObject -KeePassEntry $Entry

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .EXAMPLE
            PS> Get-KeePassEntry -KeePassonnection $DB -UserName "AUserName" | ConvertTo-KeePassPsObject

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .PARAMETER KeePassEntry
            This is the one or more KeePass Entries to be converted.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Entry')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Entry')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $KeePassEntry,

        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position = 1, ParameterSetName = 'Entry')]
        [switch] $WithCredential,

        [Parameter(Position = 2, ParameterSetName = 'Entry')]
        [switch] $AsPlainText,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName)]
        [string] $DatabaseProfileName
    )
    process
    {
        if($PSCmdlet.ParameterSetName -eq 'Entry')
        {
            foreach ($_keepassItem in $KeePassEntry)
            {
                if($WithCredential)
                {
                    try
                    {
                        $Credential = New-Object -TypeName PSCredential -ArgumentList @($_keepassItem.Strings.ReadSafe('UserName'), ($_keepassItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force -ea SilentlyContinue))
                    }
                    catch{}
                }

                if($AsPlainText)
                { $Password = $_keepassItem.Strings.ReadSafe('Password') }
                else
                { $Password = $_keepassItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force -ea SilentlyContinue }

                $KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
                        'Uuid'                    = $_keepassItem.Uuid;
                        'CreationTime'            = $_keepassItem.CreationTime;
                        'Expires'                 = $_keepassItem.Expires;
                        'ExpireTime'              = $_keepassItem.ExpiryTime;
                        'LastAccessTimeUtc'       = $_keepassItem.LastAccessTime;
                        'LastModificationTimeUtc' = $_keepassItem.LastModificationTime;
                        'LocationChanged'         = $_keepassItem.LocationChanged;
                        'Tags'                    = $_keepassItem.Tags;
                        'Touched'                 = $_keepassItem.Touched;
                        'UsageCount'              = $_keepassItem.UsageCount;
                        'ParentGroup'             = $_keepassItem.ParentGroup.Name;
                        'FullPath'                = $_keepassItem.ParentGroup.GetFullPath('/', $true);
                        'Title'                   = $_keepassItem.Strings.ReadSafe('Title');
                        'UserName'                = $_keepassItem.Strings.ReadSafe('UserName');
                        'Password'                = $Password
                        'URL'                     = $_keepassItem.Strings.ReadSafe('URL');
                        'Notes'                   = $_keepassItem.Strings.ReadSafe('Notes');
                        'IconId'                  = $_keepassItem.IconId;
                        'Credential'              = $Credential;
                        'DatabaseProfileName'     = $DatabaseProfileName;
                        'KPEntry'                 = $_keepassItem;
                    })

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Entry')

                $KeePassPsObject

                if($Password){ Remove-Variable -Name 'Password' }
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Group')
        {
            foreach ($_keepassItem in $KeePassGroup)
            {
                if($_keepassItem.ParentGroup.Name)
                { $FullPath = $_keepassItem.ParentGroup.GetFullPath('/', $true) }
                else
                { $FullPath = '' }

                $KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
                        'Uuid'                    = $_keepassItem.Uuid;
                        'Name'                    = $_keepassItem.Name;
                        'CreationTime'            = $_keepassItem.CreationTime;
                        'Expires'                 = $_keepassItem.Expires;
                        'ExpireTime'              = $_keepassItem.ExpiryTime;
                        'LastAccessTimeUtc'       = $_keepassItem.LastAccessTime;
                        'LastModificationTimeUtc' = $_keepassItem.LastModificationTime;
                        'LocationChanged'         = $_keepassItem.LocationChanged;
                        'Notes'                   = $_keepassItem.Notes;
                        'Touched'                 = $_keepassItem.Touched;
                        'UsageCount'              = $_keepassItem.UsageCount;
                        'ParentGroup'             = $_keepassItem.ParentGroup.Name;
                        'FullPath'                = $_keepassItem.GetFullPath('/', $true);
                        'Groups'                  = $_keepassItem.Groups;
                        'EntryCount'              = $_keepassItem.Entries.Count;
                        'IconId'                  = $_keepassItem.IconId;
                        'DatabaseProfileName'     = $DatabaseProfileName;
                        'KPGroup'                 = $_keepassItem;
                    })

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Group')
                $PSKeePassGroupDisplaySet = 'Name', 'EntryCount', 'FullPath', 'IconId'
                $PSKeePassGroupDefaultPropertySet = New-Object -TypeName System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [String[]] $PSKeePassGroupDisplaySet)
                $PSKeePassGroupStandardMembers = [System.Management.Automation.PSMemberInfo[]] @($PSKeePassGroupDefaultPropertySet)

                $KeePassPsObject | Add-Member MemberSet PSStandardMembers $PSKeePassGroupStandardMembers

                $KeePassPsObject
            }
        }
    }
    end
    {
        if($Credential){ Remove-Variable -Name 'Credential' }
    }
}

function Get-KeePassDatabaseConfiguration {
    <#
        .SYNOPSIS
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .DESCRIPTION
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to lookup.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration

            This Example will return all Database Configuration Profiles if any.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example returns the Database Configuration Profile with the name Personal.
        .INPUTS
            Strings
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding(DefaultParameterSetName = '__None')]
    param
    (
        [Parameter(Position = 0, ParameterSetName = '__Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, ParameterSetName = '__DefaultDB')]
        [ValidateNotNullOrEmpty()]
        [Switch] $Default,

        [Parameter(Position = 2)]
        [Switch] $Stop
    )
    process
    {
        if(Test-Path -Path $Global:KeePassConfigurationFile)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($Global:KeePassConfigurationFile)

            if($DatabaseProfileName)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -ilike $DatabaseProfileName }
            }
            elseif($Default)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Default -ieq 'true' }

                if($Stop -and -not $ProfileResults)
                {
                    throw 'Unable to find a default KeePass Configuration, please specify a database profile name or set a default profile.'
                }
            }
            else
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile
            }

            if(-not $ProfileResults -and $Stop)
            {
                throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            }

            foreach($ProfileResult in $ProfileResults)
            {
                $UseNetworkAccount = if($ProfileResult.UseNetworkAccount -eq 'True'){$true}else{$false}
                $UseMasterKey = if($ProfileResult.UseMasterKey -eq 'True'){$true}else{$false}
                $ProfileDefault = if($ProfileResult.Default -eq 'True'){$true}else{$false}

                [hashtable] $ProfileObject = [ordered]@{
                    'Name'               = $ProfileResult.Name;
                    'DatabasePath'       = $ProfileResult.DatabasePath;
                    'KeyPath'            = $ProfileResult.KeyPath;
                    'UseMasterKey'       = $UseMasterKey;
                    'UseNetworkAccount'  = $UseNetworkAccount;
                    'AuthenticationType' = $ProfileResult.AuthenticationType;
                    'Default'            = $ProfileDefault;
                }

                New-Object -TypeName PSObject -Property $ProfileObject
            }
        }
        else
        {
            Write-Warning 'The specified KeePass Configuration does not exist.'
        }
    }
}

function Get-KeePassEntry {
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Function gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the forward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass database.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER AsPSCredential
            Output Entry as an PSCredential Object
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -AsPlainText

            This Example will return all enties in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General' -AsPlainText

            This Example will return all entries in plain text format from the General folder of the keepass database with the profile name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -Title test -AsPSCredential

            This Example will return one entry as PSCredential Object
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 2, ValueFromPipelineByPropertyName)]
        [String] $Title,

        [Parameter(Position = 3)]
        [string] $UserName,

        [Parameter(Position = 4)]
        [Switch] $AsPlainText,

        [Parameter(Position = 5)]
        [Alias('AsPSCredential')]
        [Switch] $WithCredential,

        [Parameter(Position = 6, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {

        [hashtable] $params = @{
            'KeePassConnection' = $KeePassConnectionObject;
        }

        if($KeePassEntryGroupPath)
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $params.KeePassGroup = $KeePassGroup
        }

        if($Title){ $params.Title = $Title }

        if($UserName){ $params.UserName = $UserName }

        Get-KPEntry @params | ConvertTo-KeePassPsObject -AsPlainText:$AsPlainText -WithCredential:$WithCredential -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
    }
}

function Get-KeePassGroup {
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Function gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -AsPlainText

            This Example will return all groups in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -KeePassGroupPath 'General' -AsPlainText

            This Example will return all groups in plain text format from the General folder of the keepass database with the profile name TEST.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassGroupPath,

        [Parameter(Position = 2)]
        [Switch] $AsPlainText,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
        if($AsPlainText)
        { Write-Warning -Message 'The -AsPlainText switch parameter is deprecated and will be removed by end of year 2018!' }
    }
    process
    {
        [hashtable] $getKpGroupSplat = @{
            'KeePassConnection' = $KeePassConnectionObject
        }

        if($KeePassGroupPath)
        { $getKpGroupSplat.FullPath = $KeePassGroupPath }

        Get-KPGroup @getKpGroupSplat | ConvertTo-KeePassPsObject -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
    }
}

function New-KeePassConnection {
    <#
        .SYNOPSIS
            Creates an open connection to a Keepass database
        .DESCRIPTION
            Creates an open connection to a Keepass database using all available authentication methods
        .PARAMETER Database
            Path to the KeePass database (.kdbx file)
        .PARAMETER ProfileName
            Name of the profile entry
        .PARAMETER MasterKey
            Path to the keyfile (.key file) used to open the database
        .PARAMETER Keyfile
            Path to the keyfile (.key file) used to open the database
        .PARAMETER UseWindowsAccount
            Use the current windows account as an authentication method
    #>
    [CmdletBinding(DefaultParameterSetName = '__None')]
    param
    (
        [Parameter(Position = 0, ParameterSetName = 'Profile')]
        [AllowNull()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 0, Mandatory, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $Database,

        [Parameter(Position = 2, ParameterSetName = 'CompositeKey')]
        [Parameter(Position = 1, ParameterSetName = 'Profile')]
        [AllowNull()]
        [PSObject] $MasterKey,

        [Parameter(Position = 1, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $KeyPath,

        [Parameter(Position = 3, ParameterSetName = 'CompositeKey')]
        [Switch] $UseWindowsAccount
    )
    process
    {
        try
        {
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }
        catch
        {
            Write-Error -Message 'Unable to Create KeepassLib.PWDatabase to open a connection.' -Exception $_.Exception -ea Stop
        }

        $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

        if(($MasterKey -isnot [PSCredential]) -and ($MasterKey -isnot [SecureString]) -and $MasterKey)
        {
            Write-Error -Message ('[PROCESS] The MasterKey of type: ({0}). Is not Supported Please supply a MasterKey of Types (SecureString or PSCredential).' -f $($MasterKey.GetType().Name)) -Category InvalidType -TargetObject $MasterKey -RecommendedAction 'Provide a MasterKey of Type PSCredential or SecureString'
        }

        if($PSCmdlet.ParameterSetName -eq 'Profile' -or $PSCmdlet.ParameterSetName -eq '__None')
        {
            ## if not passing a profile name, attempt to get the default db
            $getKeePassDatabaseConfigurationSplat = @{ Stop = $true }
            if($DatabaseProfileName){ $getKeePassDatabaseConfigurationSplat.DatabaseProfileName = $DatabaseProfileName }
            else{ $getKeePassDatabaseConfigurationSplat.Default = $true }

            $KeepassConfigurationObject = Get-KeePassDatabaseConfiguration @getKeePassDatabaseConfigurationSplat

            $Database = $KeepassConfigurationObject.DatabasePath
            if(-not [string]::IsNullOrEmpty($KeepassConfigurationObject.KeyPath)){ $KeyPath = $KeepassConfigurationObject.KeyPath }
            [Switch] $UseWindowsAccount = $KeepassConfigurationObject.UseNetworkAccount
            [Switch] $UseMasterKey = $KeepassConfigurationObject.UseMasterKey

            if($UseMasterKey -and -not $MasterKey)
            {
                $MasterKey = Read-Host -Prompt 'KeePass Password' -AsSecureString
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'CompositeKey')
        {
            $UseMasterKey = if($MasterKey){ $true }
        }

        if($MasterKey -is [PSCredential])
        {
            [SecureString] $MasterKey = $MasterKey.Password
        }

        $DatabaseItem = Get-Item -Path $Database -ErrorAction Stop

        ## Start Building CompositeKey
        ## Order in which the CompositeKey is created is important and must follow the order of : MasterKey, KeyFile, Windows Account
        if($UseMasterKey)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterKey)))))
        }

        if($KeyPath)
        {
            try
            {
                $KeyPathItem = Get-Item $KeyPath -ErrorAction Stop
                $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpKeyfile($KeyPathItem.FullName)))
            }
            catch
            {
                Write-Warning ('Could not read the specfied Key file [{0}].' -f $KeyPathItem.FullName)
            }
        }

        if($UseWindowsAccount)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
        }

        ## Build and Open Connection
        $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
        $IOInfo.Path = $DatabaseItem.FullName

        ## We currently are not using a status logger hence the null.
        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

        $null = $DatabaseObject.Open($IOInfo, $CompositeKey, $IStatusLogger)
        $DatabaseObject

        if(-not $DatabaseObject.IsOpen)
        {
            Throw 'InvalidDatabaseConnectionException : The database is not open.'
        }
    }
}

function New-KeePassDatabase {
    <#
        .SYNOPSIS
            Function to create a keepass database.
        .DESCRIPTION
            This function creates a new keepass database
        .PARAMETER DatabasePath
            Path to the Keepass database (.kdbx file)
        .PARAMETER KeyPath
            Not yet implemented
        .PARAMETER UseNetworkAccount
            Specify of you want the database to use windows authentication
        .PARAMETER MasterKey
            The masterkey that provides access to the database
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabasePath,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 2, ParameterSetName = 'Key')]
        [Parameter(Position = 2, ParameterSetName = 'Master')]
        [Parameter(Position = 2, Mandatory, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 3, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 3, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [PSCredential] $MasterKey
    )
    begin
    {
        if($KeyPath)
        { throw "KeyPath is not implemented yet" }
    }
    process
    {
        if(Test-Path -Path $DatabasePath)
        {
            throw ('The specified Database Path already exists: {0}.' -f $DatabasePath)
        }
        else
        {
            try
            {
                $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
            }
            catch
            {
                Import-KPLibrary
                $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
            }

            $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

            if($MasterKey)
            {
                $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($MasterKey.GetNetworkCredential().Password)
                $CompositeKey.AddUserKey($KcpPassword)
            }

            if($UseNetworkAccount)
            {
                $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
            }

            $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
            $IOInfo.Path = $DatabasePath

            $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

            $DatabaseObject.New($IOInfo, $CompositeKey) | Out-Null
            $DatabaseObject.Save($IStatusLogger)
        }
    }
}

function New-KeePassDatabaseConfiguration {
    <#
        .SYNOPSIS
            Function to Create or Add a new KeePass Database Configuration Profile to the KeePassConfiguration.xml
        .DESCRIPTION
            The Profile Created will be accessible from the core functions Get,Update,New,Remove KeePassEntry and ect.
            The Profile stores database configuration for opening and authenticating to a keepass database.
            Using the configuration allows for speedier authentication and less complex commands.
        .PARAMETER DatabaseProfileName
            Specify the Name of the new Database Configuration Profile.
        .PARAMETER DatabasePath
            Specify the Path to the database (.kdbx) file.
        .PARAMETER KeyPath
            Specify the Path to the database (.key) key file if there is one.
        .PARAMETER UseNetworkAccount
            Specify this flag if the database uses NetworkAccount Authentication.
        .PARAMETER UseMasterKey
            Specify this flag if the database uses a Master Key Password for Authentication.
        .PARAMETER PassThru
            Specify to return the new database configuration profile object.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -KeyPath 'c:\users\username\documents\personal.key' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Key File and Uses NetworkAccount.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Uses NetworkAccount.
        .NOTES
            1. Currently all authentication combinations are supported except keyfile, masterkey password, and network authentication together.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Network')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $DatabasePath,

        [Parameter(Position = 2, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 2, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 3, ParameterSetName = 'Key')]
        [Parameter(Position = 3, ParameterSetName = 'Master')]
        [Parameter(Position = 3, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 4, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 4, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [Switch] $UseMasterKey,

        [Parameter(Position = 5)]
        [Switch] $Default,

        [Parameter(Position = 6)]
        [Switch] $PassThru
    )
    begin
    {
        if($PSCmdlet.ParameterSetName -eq 'Network' -and -not $UseNetworkAccount)
        {
            Write-Warning -Message '[BEGIN] Please Specify a valid Credential Combination.'
            Write-Warning -Message '[BEGIN] You can not have a only a database file with no authentication options.'
            Throw 'Please Specify a valid Credential Combination.'
        }
    }
    process
    {
        if (-not (Test-Path -Path $Global:KeePassConfigurationFile))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist. One will be generated now.'
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if($CheckIfProfileExists)
        {
            Write-Warning -Message ('[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName)
            Throw '[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName
        }
        else
        {
            try
            {
                if($Default)
                {
                    $defaultProfile = Get-KeePassDatabaseConfiguration -Default

                    if($defaultProfile)
                    {
                        throw ('{0} profile is already set to the default, if you would like to overwrite it as the default please use the Update-KeePassDatabaseConfiguration function and remove the default flag.' -f $defaultProfile.Name)
                    }
                }

                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($Global:KeePassConfigurationFile)
                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $DatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null

                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element', 'DatabasePath', '')
                $DatabasePathNode.InnerText = $DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null

                $KeyPathNode = $XML.CreateNode('element', 'KeyPath', '')
                $KeyPathNode.InnerText = $KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null

                $UseNetworkAccountNode = $XML.CreateNode('element', 'UseNetworkAccount', '')
                $UseNetworkAccountNode.InnerText = $UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null

                $UseMasterKeyNode = $XML.CreateNode('element', 'UseMasterKey', '')
                $UseMasterKeyNode.InnerText = $UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null

                $AuthenticationTypeNode = $XML.CreateNode('element', 'AuthenticationType', '')
                $AuthenticationTypeNode.InnerText = $PSCmdlet.ParameterSetName
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $DefaultNode = $XML.CreateNode('element', 'Default', '')
                $DefaultNode.InnerText = $Default
                $DatabaseProfile.AppendChild($DefaultNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').AppendChild($DatabaseProfile) | Out-Null

                $XML.Save($Global:KeePassConfigurationFile)

                $Script:KeePassProfileNames = (Get-KeePassDatabaseConfiguration).Name

                if($PassThru)
                {
                    Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
                }
            }
            catch
            {
                Write-Warning -Message ('[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ({0}) to the configuration file.' -f $DatabaseProfileName)
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}

function New-KeePassEntry {
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER Tags
            Specify the Tags of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the newly created keepass database entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example creates a new keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName = 'Key',

        [Parameter(Position = 8)]
        [switch] $Expires,

        [Parameter(Position = 9)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 10)]
        [ValidateNotNullOrEmpty()]
        [String[]] $Tags,

        [Parameter(Position = 11, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 12)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 13)]
        [Switch] $PassThru
    )
    begin
    {
    }
    process
    {
        try
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $addKpEntrySplat = @{
                URL               = $URL
                UserName          = $UserName
                IconName          = $IconName
                KeePassGroup      = $KeePassGroup
                KeePassPassword   = $KeePassPassword
                PassThru          = $PassThru
                Title             = $Title
                KeePassConnection = $KeePassConnectionObject
                Notes             = $Notes
                Tags              = $Tags
            }

            if(Test-Bound -ParameterName 'Expires'){ $addKpEntrySplat.Expires = $Expires }
            if($ExpiryTime){ $addKpEntrySplat.ExpiryTime = $ExpiryTime }

            Add-KpEntry @addKpEntrySplat | ConvertTo-KeePassPsObject -DatabaseProfileName $DatabaseProfileName
        }
        catch
        { Throw $_ }
    }
    end
    {
    }
}

function New-KeePassGroup {
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER KeePassGroupName
            Specify the Name of the new KeePass Group.
        .PARAMETER PassThru
            Specify to return the new group object.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> New-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts' -KeePassGroupName 'TestGroup'

            This Example Creates a Group Called 'TestGroup' in the Group Path 'General/TestAccounts'
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassGroupParentPath,

        [Parameter(Position = 2, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName = 'Folder',

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 5)]
        [switch] $Expires,

        [Parameter(Position = 6)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 7, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 8)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 9)]
        [Switch] $PassThru
    )
    begin
    {
    }
    process
    {
        $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupParentPath -Stop

        $addKPGroupSplat = @{
            KeePassConnection  = $KeePassConnectionObject
            GroupName          = $KeePassGroupName
            IconName           = $IconName
            PassThru           = $PassThru
            KeePassParentGroup = $KeePassParentGroup
            Notes              = $Notes
        }

        # if($Notes){ $addKPGroupSplat.Notes = $Notes }
        if(Test-Bound -ParameterName 'Expires'){ $addKPGroupSplat.Expires = $Expires }
        if($ExpiryTime){ $addKPGroupSplat.ExpiryTime = $ExpiryTime }

        Add-KPGroup @addKPGroupSplat | ConvertTo-KeePassPsObject -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
    }
}

function New-KeePassPassword {
    <#
        .SYNOPSIS
            This Function will Generate a New Password.
        .DESCRIPTION
            This Function will Generate a New Password with the Specified rules using the KeePass-
            Password Generator.

            This Contains the Majority of the Options including the advanced options that the KeePass-
            UI provides in its "PasswordGenerator Form".

            Currently this function does not support the use of previously saved/created Password Profiles-
            aka KeePassLib.Security.PasswordGenerator.PwProfile. Nore does it support Saving a New Profile.

            This Simply Applies the Rules specified and generates a new password that is returned in the form-
            of a KeePassLib.Security.ProtectedString.
        .EXAMPLE
            PS> New-KeePassPassword

            This Example will generate a Password using the Default KeePass Password Profile.
            Which is is -UpperCase -LowerCase -Digites -Length 20
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -Length 20

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -Length 20 -SaveAs 'Basic Password'

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9.
            Then it will save it as a password profile with the bane 'Basic Password' for future reuse.
        .EXAMPLE
            PS> New-KeePassPassword -PasswordProfileName 'Basic Password'

            This Example will generate a password using the password profile name Basic Password.
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -ExcludeCharacters '"' -Length 20

            This Example will generate a Password with the Specified Options and Exclude the Double Quote Character
        .PARAMETER UpperCase
            If Specified it will add UpperCase Letters to the character set used to generate the password.
        .PARAMETER LowerCase
            If Specified it will add LowerCase Letters to the character set used to generate the password.
        .PARAMETER Digits
            If Specified it will add Digits to the character set used to generate the password.
        .PARAMETER SpecialCharacters
            If Specified it will add Special Characters '!"#$%&''*+,./:;=?@\^`|~' to the character set used to generate the password.
        .PARAMETER Minus
            If Specified it will add the Minus Symbol '-' to the character set used to generate the password.
        .PARAMETER UnderScore
            If Specified it will add the UnderScore Symbol '_' to the character set used to generate the password.
        .PARAMETER Space
            If Specified it will add the Space Character ' ' to the character set used to generate the password.
        .PARAMETER Brackets
            If Specified it will add Bracket Characters '()<>[]{}' to the character set used to generate the password.
        .PARAMETER ExcludeLookAlike
            If Specified it will exclude Characters that Look Similar from the character set used to generate the password.
        .PARAMETER NoRepeatingCharacters
            If Specified it will only allow Characters exist once in the password that is returned.
        .PARAMETER ExcludeCharacters
            This will take a list of characters to Exclude, and remove them from the character set used to generate the password.
        .PARAMETER Length
            This will specify the length of the resulting password. If not used it will use KeePass's Default Password Profile
            Length Value which I believe is 20.
        .PARAMETER SaveAS
            Specify the name in which you wish to save the password configuration as.
            This will save all specified settings the KeePassConfiguration.xml file, which can then be specifed later when genreating a password to match the same settings.
        .PARAMETER PasswordProfileName
            *Specify this parameter to use a previously saved password profile to genreate a password.
            *Note:
                *This supports Tab completion as it will get all saved profiles.
        .INPUTS
            String
            Switch
        .OUTPUTS
            KeePassLib.Security.ProtectedString
    #>
    [CmdletBinding(DefaultParameterSetName = 'NoProfile')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName,

        [Parameter(Position = 0, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UpperCase,

        [Parameter(Position = 1, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $LowerCase,

        [Parameter(Position = 2, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Digits,

        [Parameter(Position = 3, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $SpecialCharacters,

        [Parameter(Position = 4, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Minus,

        [Parameter(Position = 5, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UnderScore,

        [Parameter(Position = 6, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Space,

        [Parameter(Position = 7, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Brackets,

        [Parameter(Position = 8, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $ExcludeLookALike,

        [Parameter(Position = 9, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $NoRepeatingCharacters,

        [Parameter(Position = 10, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $ExcludeCharacters,

        [Parameter(Position = 11, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [Int] $Length,

        [Parameter(Position = 12, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $SaveAs
    )
    begin
    {
    }
    process
    {
        ## Create New Password Profile.
        $PassProfile = New-Object KeePassLib.Cryptography.PasswordGenerator.PwProfile

        if($PSCmdlet.ParameterSetName -eq 'NoProfile')
        {
            $NewProfileObject = '' | Select-Object ProfileName, CharacterSet, ExcludeLookAlike, NoRepeatingCharacters, ExcludeCharacters, Length
            if($PSBoundParameters.Count -gt 0)
            {
                $PassProfile.CharSet = New-Object KeePassLib.Cryptography.PasswordGenerator.PwCharSet

                if($UpperCase)
                {
                    $NewProfileObject.CharacterSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                }

                if($LowerCase)
                {
                    $NewProfileObject.CharacterSet += 'abcdefghijklmnopqrstuvwxyz'
                }

                if($Digits)
                {
                    $NewProfileObject.CharacterSet += '0123456789'
                }

                if($SpecialCharacters)
                {
                    $NewProfileObject.CharacterSet += '!"#$%&''*+,./:;=?@\^`|~'
                }

                if($Minus)
                {
                    $NewProfileObject.CharacterSet += '-'
                }

                if($UnderScore)
                {
                    $NewProfileObject.CharacterSet += '_'
                }

                if($Space)
                {
                    $NewProfileObject.CharacterSet += ' '
                }

                if($Brackets)
                {
                    $NewProfileObject.CharacterSet += '[]{}()<>'
                }

                if($ExcludeLookALike)
                {
                    $NewProfileObject.ExcludeLookAlike = $true
                }
                else
                {
                    $NewProfileObject.ExcludeLookAlike = $false
                }

                if($NoRepeatingCharacters)
                {
                    $NewProfileObject.NoRepeatingCharacters = $true
                }
                else
                {
                    $NewProfileObject.NoRepeatingCharacters = $false
                }

                if($ExcludeCharacters)
                {
                    $NewProfileObject.ExcludeCharacters = $ExcludeCharacters
                }
                else
                {
                    $NewProfileObject.ExcludeCharacters = ''
                }

                if($Length)
                {
                    $NewProfileObject.Length = $Length
                }
                else
                {
                    $NewProfileObject.Length = '20'
                }

                $PassProfile.CharSet.Add($NewProfileObject.CharacterSet)
                $PassProfile.ExcludeLookAlike = $NewProfileObject.ExlcudeLookAlike
                $PassProfile.NoRepeatingCharacters = $NewProfileObject.NoRepeatingCharacters
                $PassProfile.ExcludeCharacters = $NewProfileObject.ExcludeCharacters
                $PassProfile.Length = $NewProfileObject.Length
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Profile')
        {
            $PasswordProfileObject = Get-KPPasswordProfile -PasswordProfileName $PasswordProfileName

            if(-not $PasswordProfileObject)
            {
                Write-Error -Message ('No KPPasswordProfile could be found with the specified Name: ' + $PasswordProfileName) -TargetObject $PasswordProfileName -Category ObjectNotFound -ErrorAction Stop
            }

            $PassProfile.CharSet.Add($PasswordProfileObject.CharacterSet)
            $PassProfile.ExcludeLookAlike = if($PasswordProfileObject.ExlcudeLookAlike -eq 'True'){$true}else{$false}
            $PassProfile.NoRepeatingCharacters = if($PasswordProfileObject.NoRepeatingCharacters -eq 'True'){$true}else{$false}
            $PassProfile.ExcludeCharacters = $PasswordProfileObject.ExcludeCharacters
            $PassProfile.Length = $PasswordProfileObject.Length
        }

        ## Create Pass Generator Profile Pool.
        $GenPassPool = New-Object KeePassLib.Cryptography.PasswordGenerator.CustomPwGeneratorPool
        ## Create Out Parameter aka [rel] param.
        [KeePassLib.Security.ProtectedString]$PSOut = New-Object KeePassLib.Security.ProtectedString
        ## Generate Password.
        $ResultMessage = [KeePassLib.Cryptography.PasswordGenerator.PwGenerator]::Generate([ref] $PSOut, $PassProfile, $null, $GenPassPool)
        ## Check if Password Generation was successful
        if($ResultMessage -ne 'Success')
        {
            Write-Warning -Message '[PROCESS] Failure while attempting to generate a password with the specified settings or profile.'
            Write-Warning -Message ('[PROCESS] Password Generation Failed with the Result Text: {0}.' -f $ResultMessage)
            if($ResultMessage -eq 'TooFewCharacters')
            {
                Write-Warning -Message ('[PROCESS] Result Text {0}, typically means that you specified a length that is longer than the possible generated outcome.' -f $ResultMessage)
                $ExcludeCharacterCount = if($PassProfile.ExcludeCharacters){($PassProfile.ExcludeCharacters -split ',').Count}else{0}
                if($PassProfile.NoRepeatingCharacters -and $PassProfile.Length -gt ($PassProfile.CharSet.Size - $ExcludeCharacterCount))
                {
                    Write-Warning -Message "[PROCESS] Checked for the invalid specification. `n`tSpecified Length: $($PassProfile.Length). `n`tCharacterSet Count: $($PassProfile.CharSet.Size). `n`tNo Repeating Characters is set to: $($PassProfile.NoRepeatingCharacters). `n`tExclude Character Count: $ExcludeCharacterCount."
                    Write-Warning -Message '[PROCESS] Specify More characters, shorten the length, remove the no repeating characters option, or removed excluded characters.'
                }
            }

            Throw 'Unabled to generate a password with the specified options.'
        }
        else
        {
            if($SaveAs)
            {
                $NewProfileObject.ProfileName = $SaveAs
                New-KPPasswordProfile -KeePassPasswordObject $NewProfileObject
            }
        }

        try
        {
            $PSOut
        }
        catch
        {
            Write-Warning -Message '[PROCESS] An exception occured while trying to convert the KeePassLib.Securtiy.ProtectedString to a SecureString.'
            Write-Warning -Message ('[PROCESS] Exception Message: {0}' -f $_.Exception.Message)
            Throw $_
        }
    }
    end
    {
        if($PSOut){Remove-Variable -Name PSOUT}
    }
}

function Remove-KeePassConnection {
    <#
        .SYNOPSIS
            This Function Removes a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Removes a Connection to a KeePass Database.
        .EXAMPLE
            PS> Remove-KeePassConnection -KeePassConnection $DB

            This Example will Remove/Close a KeePass Database Connection using a pre-defined KeePass DB connection.
        .PARAMETER KeePassConnection
            This is the KeePass Connection to be Closed
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection
    )
    process
    {
        try
        {
            if($KeePassConnection.IsOpen)
            {
                $KeePassConnection.Close()
            }
            else
            {
                Write-Warning -Message '[PROCESS] The KeePass Database Specified is already closed or does not exist.'
                Write-Error -Message 'The KeePass Database Specified is already closed or does not exist.' -ea Stop
            }
        }
        catch [Exception]
        {
            Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
}

function Remove-KeePassDatabaseConfiguration {
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Configuration Profile.
        .DESCRIPTION
            This function allows a specified database configuration profile to be removed from the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to be deleted.
        .EXAMPLE
            PS> Remove-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example will remove the database configuration profile 'Personal' from the KeePassConfiguration.xml file.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string] $DatabaseProfileName
    )
    begin
    {
    }
    process
    {
        if($PSCmdlet.ShouldProcess($DatabaseProfileName))
        {
            try
            {
                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($Global:KeePassConfigurationFile)
                $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -eq $DatabaseProfileName } | ForEach-Object { $xml.Settings.DatabaseProfiles.RemoveChild($_) } | Out-Null
                $XML.Save($Global:KeePassConfigurationFile)
            }
            catch
            {
                Write-Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Database Configuration Profile ({0}).' -f $DatabaseProfileName)
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}

function Remove-KeePassEntry {
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Entry.
        .DESCRIPTION
            This function removed a KeePass Database Entry.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassEntry
            The KeePass Entry to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the entry and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassEntry -KeePassEntry $KeePassEntryObject

            This example removed the specified kee pass entry.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 2)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3)]
        [Switch] $Force,

        [Parameter(Position = 4, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {
        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        $EntryDisplayName = '{0}/{1}' -f $KPEntry.ParentGroup.GetFullPath('/', $true), $KPEntry.Strings.ReadSafe('Title')
        if($Force -or $PSCmdlet.ShouldProcess($EntryDisplayName))
        {
            [hashtable] $params = @{
                'KeePassConnection' = $KeePassConnectionObject;
                'KeePassEntry'      = $KPEntry;
                'Confirm'           = $false;
                'Force'             = $Force;
            }

            if($NoRecycle){ $params.NoRecycle = $NoRecycle }
            Remove-KPEntry @params
        }
    }
    end
    {
    }
}

function Remove-KeePassGroup {
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Group.
        .DESCRIPTION
            This function removed a KeePass Database Group.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.    
        .PARAMETER KeePassGroup
            The KeePass Group to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the Group and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the Group.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassGroup -KeePassGroup $KeePassGroupObject

            This example removed the specified keepass Group.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 2)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3)]
        [Switch] $Force,

        [Parameter(Position = 4, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {
        $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroup.FullPath -Stop | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime}

        if($KeePassGroupObject.Count -gt 1)
        {
            Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Removal.'
            Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups.' -f $KeePassGroupObject.Count)
            Throw 'Found more than one group with the same path, name and creation time. Stoping Removal.'
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroup.FullPath))
        {
            if(-not $NoRecycle)
            {
                Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -Confirm:$false -Force
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Remove this Group permanetly: $KeePassGroup.FullPath?"))
                {
                    Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -NoRecycle:$NoRecycle -Confirm:$false -Force
                }
            }
        }
    }
    end
    {
    }
}

function Update-KeePassDatabaseConfiguration {
    <#
        .SYNOPSIS
            Function to Update a KeePass Database Configuration Profile in the KeePassConfiguration.xml
        .DESCRIPTION
            The Profile Created will be accessible from the core functions Get,Update,New,Remove KeePassEntry and ect.
            The Profile stores database configuration for opening and authenticating to a keepass database.
            Using the configuration allows for speedier authentication and less complex commands.
        .PARAMETER DatabaseProfileName
            Specify the Name of the new Database Configuration Profile.
        .PARAMETER DatabasePath
            Specify the Path to the database (.kdbx) file.
        .PARAMETER KeyPath
            Specify the Path to the database (.key) key file if there is one.
        .PARAMETER UseNetworkAccount
            Specify this flag if the database uses NetworkAccount Authentication.
        .PARAMETER UseMasterKey
            Specify this flag if the database uses a Master Key Password for Authentication.
        .PARAMETER PassThru
            Specify to return the new database configuration profile object.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -KeyPath 'c:\users\username\documents\personal.key' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Key File and Uses NetworkAccount.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Uses NetworkAccount.
        .NOTES
            1. Currently all authentication combinations are supported except keyfile, masterkey password, and network authentication together.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(DefaultParameterSetName = '_none')]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $NewDatabaseProfileName = $DatabaseProfileName,

        [Parameter(Position = 2, ParameterSetName = 'Key')]
        [Parameter(Position = 2, ParameterSetName = 'Master')]
        [Parameter(Position = 2, ParameterSetName = 'Network')]
        [Parameter(Position = 2, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $DatabasePath,

        [Parameter(Position = 2, ParameterSetName = 'Key')]
        [Parameter(Position = 2, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 4, ParameterSetName = 'Key')]
        [Parameter(Position = 4, ParameterSetName = 'Master')]
        [Parameter(Position = 4, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 5, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 5, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [Switch] $UseMasterKey,

        [Parameter(Position = 6)]
        [Switch] $Default,

        [Parameter(Position = 7)]
        [Switch] $PassThru
    )
    begin
    {
        if($PSCmdlet.ParameterSetName -eq 'Network' -and -not $UseNetworkAccount)
        {
            Write-Warning -Message '[BEGIN] Please Specify a valid Credential Combination.'
            Write-Warning -Message '[BEGIN] You can not have only a database file with no authentication options.'
            throw 'Please Specify a valid Credential Combination.'
        }
    }
    process
    {
        # throw 'Update-KeePassDatabaseConfiguration not yet implemented.'

        if (-not (Test-Path -Path $Global:KeePassConfigurationFile))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist. One will be generated now.'
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if(-not $CheckIfProfileExists)
        {
            Write-Warning -Message ('[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: {0}.' -f $DatabaseProfileName)
            throw '[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: {0}.' -f $DatabaseProfileName
        }
        else
        {
            if($Default)
            {
                $defaultProfile = Get-KeePassDatabaseConfiguration -Default

                if($defaultProfile -and $defaultProfile.Name -ine $DatabaseProfileName)
                {
                    throw ('{0} profile is already set to the default, if you would like to overwrite it as the default please use the Update-KeePassDatabaseConfiguration function and remove the default flag.' -f $defaultProfile.Name)
                }
            }

            try
            {
                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($Global:KeePassConfigurationFile)

                $OldProfile = $XML.SelectNodes('/Settings/DatabaseProfiles/Profile') | Where-Object { $_.Name -eq $DatabaseProfileName }
                if(-not $DatabasePath){ $_DatabasePath = $OldProfile.DatabasePath }
                if(Test-Bound -ParameterName 'UseMasterKey' -Not){ $_UseMasterKey = [bool]::Parse($OldProfile.UseMasterKey) }
                if(-not $KeyPath){ $_KeyPath = $OldProfile.KeyPath}
                if(Test-Bound -ParameterName 'UseNetworkAccount' -Not){ $_UseNetworkAccount = [bool]::Parse($OldProfile.UseNetworkAccount) }

                if($PSCmdlet.ParameterSetName -eq '_none'){ $_AuthenticationType = $OldProfile.AuthenticationType }
                else{ $_AuthenticationType = $PSCmdlet.ParameterSetName}

                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $NewDatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null

                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element', 'DatabasePath', '')
                $DatabasePathNode.InnerText = $_DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null

                $KeyPathNode = $XML.CreateNode('element', 'KeyPath', '')
                $KeyPathNode.InnerText = $_KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null

                $UseNetworkAccountNode = $XML.CreateNode('element', 'UseNetworkAccount', '')
                $UseNetworkAccountNode.InnerText = $_UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null

                $UseMasterKeyNode = $XML.CreateNode('element', 'UseMasterKey', '')
                $UseMasterKeyNode.InnerText = $_UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null

                $AuthenticationTypeNode = $XML.CreateNode('element', 'AuthenticationType', '')
                $AuthenticationTypeNode.InnerText = $_AuthenticationType
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $DefaultNode = $XML.CreateNode('element', 'Default', '')
                $DefaultNode.InnerText = $Default
                $DatabaseProfile.AppendChild($DefaultNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').ReplaceChild($DatabaseProfile, $OldProfile) | Out-Null

                $XML.Save($Global:KeePassConfigurationFile)

                $Script:KeePassProfileNames = (Get-KeePassDatabaseConfiguration).Name

                if($PassThru)
                {
                    Get-KeePassDatabaseConfiguration -DatabaseProfileName $NewDatabaseProfileName
                }
            }
            catch
            {
                Write-Warning -Message ('[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ({0}) to the configuration file.' -f $NewDatabaseProfileName)
                Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}

function Update-KeePassEntry {
    <#
        .SYNOPSIS
            Function to update a KeePass Database Entry.
        .DESCRIPTION
            This function updates a KeePass Database Entry with basic properites available for specification.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassEntry
            The KeePass Entry to be updated. Use the Get-KeePassEntry function to get this object.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries for a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER Tags
            Specify the Tags of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the modified object.
        .PARAMETER Force
            Specify to Update the specified entry without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example updates a keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName,

        [Parameter(Position = 8)]
        [switch] $Expires,

        [Parameter(Position = 9)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 10)]
        [ValidateNotNullOrEmpty()]
        [String[]] $Tags,

        [Parameter(Position = 11, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 12)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 13)]
        [Switch] $PassThru,

        [Parameter(Position = 14)]
        [Switch] $Force
    )
    begin
    {
    }
    process
    {
        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        $KeePassEntryGroupPath = $KeePassEntry.FullPath
        if(-not $KPEntry)
        {
            Write-Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        if($Force -or $PSCmdlet.ShouldProcess("Title: $($KPEntry.Strings.ReadSafe('Title')), `n`tUserName: $($KPEntry.Strings.ReadSafe('UserName')), `n`tGroupPath: $($KPEntry.ParentGroup.GetFullPath('/', $true))."))
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $setKPEntrySplat = @{
                URL               = $URL
                KeePassEntry      = $KPEntry
                UserName          = $UserName
                Notes             = $Notes
                KeePassPassword   = $KeePassPassword
                KeePassGroup      = $KeePassGroup
                PassThru          = $PassThru
                Force             = $true
                Title             = $Title
                Tags              = $Tags
                KeePassConnection = $KeePassConnectionObject
            }

            if($IconName){ $setKPEntrySplat.IconName = $IconName }
            if(Test-Bound -ParameterName 'Expires'){ $setKPEntrySplat.Expires = $Expires }
            if($ExpiryTime){ $setKPEntrySplat.ExpiryTime = $ExpiryTime}

            Set-KPEntry @setKPEntrySplat | ConvertTo-KeePassPsObject -DatabaseProfileName $DatabaseProfileName
        }
    }
    end
    {
    }
}

function Update-KeePassGroup {
    <#
        .SYNOPSIS
            Function to update a KeePass Database Group.
        .DESCRIPTION
            This function updates a KeePass Database Group.
        .PARAMETER KeePassConnectionObject
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassGroup
            The KeePass Group to be updated. Use the Get-KeePassGroup function to get this object.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish move the specified group to a different parent group.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER GroupName
            Specify the GroupName to change the specified group to.
        .PARAMETER PassThru
            Specify to return the updated keepass group object.
        .PARAMETER Force
            Specify to Update the specified group without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> Update-KeePassGroup -DatabaseProfileName TEST -KeePassGroup $KeePassGroupObject -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves the specified KeePassGroup to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves group specified via the pipeline to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -GroupName 'DevGroup'

            This Example renames the group specified via the pipeline to 'DevGroup'
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnectionObject,
        
        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassParentGroupPath,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 4)]
        [switch] $Expires,

        [Parameter(Position = 5)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 6, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 8)]
        [Switch] $PassThru,

        [Parameter(Position = 9)]
        [Switch] $Force
    )
    begin
    {
    }
    process
    {
        if($KeePassParentGroupPath -and $KeePassParentGroupPath -ne $KeePassGroup.FullPath)
        {
            $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassParentGroupPath -Stop
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroup.FullPath))
        {
            $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroup.FullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime }

            if($KeePassGroupObject.Count -gt 1)
            {
                Write-Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Update.'
                Write-Warning -Message ('[PROCESS] Found: ({0}) number of matching groups' -f $KeePassGroupObject.Count)
                Throw 'Found more than one group with the same path, name and creation time.'
            }

            $setKPGroupSplat = @{
                KeePassConnection = $KeePassConnectionObject
                KeePassGroup      = $KeePassGroupObject
                PassThru          = $PassThru
                Force             = $true
                GroupName         = $GroupName
                Confirm           = $false
                Notes             = $Notes
            }

            if($IconName){ $setKPGroupSplat.IconName = $IconName }
            if($KeePassParentGroup){ $setKPGroupSplat.KeePassParentGroup = $KeePassParentGroup }
            if(Test-Bound -ParameterName 'Expires'){ $setKPGroupSplat.Expires = $Expires }
            if($ExpiryTime){ $setKPGroupSplat.ExpiryTime = $ExpiryTime }

            Set-KPGroup @setKPGroupSplat | ConvertTo-KeePassPsObject -DatabaseProfileName $DatabaseProfileName
        }
    }
    end
    {
    }
}

