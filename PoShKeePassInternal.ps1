function Add-KPEntry {
    <#
        .SYNOPSIS
            This Function will add a new entry to a KeePass Database Group.
        .DESCRIPTION
            This Function will add a new entry to a KeePass Database Group.

            Currently This function supportes the basic fields for creating a new KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            This is the KeePass GroupObject to add the new Entry to.
        .PARAMETER Title
            This is the Title of the New KeePass Entry.
        .PARAMETER UserName
            This is the UserName of the New KeePass Entry.
        .PARAMETER KeePassPassword
            This is the Password of the New KeePass Entry.
        .PARAMETER Notes
            This is the Notes of the New KeePass Entry.
        .PARAMETER URL
            This is the URL of the New KeePass Entry.
        .PARAMETER Tags
            Specify the Tags of the new KeePass Database Entry.
        .PARAMETER PassThru
            Returns the New KeePass Entry after creation.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2)]
        [String] $Title,

        [Parameter(Position = 3)]
        [String] $UserName,

        [Parameter(Position = 4)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [String] $URL,

        [Parameter(Position = 7)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 8)]
        [bool] $Expires,

        [Parameter(Position = 9)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 10)]
        [String[]] $Tags,

        [Parameter(Position = 11)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwEntry] $KeePassEntry = New-Object KeePassLib.PwEntry($true, $true) -ea Stop
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if((Test-KPPasswordValue $KeePassPassword) -and (Test-KPConnection $KeePassConnection))
        {
            if($Title)
            {
                [KeePassLib.Security.ProtectedString] $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                $KeePassEntry.Strings.Set('Title', $SecureTitle)
            }

            if($UserName)
            {
                [KeePassLib.Security.ProtectedString] $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                $KeePassEntry.Strings.Set('UserName', $SecureUser)
            }

            if($KeePassPassword)
            {
                if($KeePassPassword.GetType().Name -eq 'SecureString')
                {
                    [KeePassLib.Security.ProtectedString] $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                    $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                }
                elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                {
                    $KeePassSecurePasswordString = $KeePassPassword
                }
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }
            else
            {
                ## get password based on default pattern
                $KeePassSecurePasswordString = New-KeePassPassword
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }

            if($Notes)
            {
                [KeePassLib.Security.ProtectedString] $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                $KeePassEntry.Strings.Set('Notes', $SecureNotes)
            }

            if($URL)
            {
                [KeePassLib.Security.ProtectedString] $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                $KeePassEntry.Strings.Set('URL', $SecureURL)
            }

            if($IconName -and $IconName -ne $KeePassEntry.IconId)
            {
                $KeePassEntry.IconId = $IconName
            }

            if(Test-Bound -ParameterName 'Expires')
            {
                $KeePassEntry.Expires = $Expires
            }

            if($ExpiryTime)
            {
                $KeePassEntry.ExpiryTime = $ExpiryTime.ToUniversalTime()
            }

            if($Tags)
            {
                $Tags | ForEach-Object { $null = $KeePassEntry.AddTag($_) }
            }

            $KeePassGroup.AddEntry($KeePassEntry, $true)

            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassEntry
            }
        }
    }
}

function Add-KPGroup {
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the connection Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER PassThru
            Specify to return the new keepass group object.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullorEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 3)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 4)]
        [String] $Notes,

        [Parameter(Position = 5)]
        [bool] $Expires,

        [Parameter(Position = 6)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 7)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ea Stop
        }
        catch
        {
            Write-Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            $KeePassGroup.Name = $GroupName

            if($IconName -and $IconName -ne $KeePassGroup.IconId)
            {
                $KeePassGroup.IconId = $IconName
            }

            if($Notes)
            {
                $KeePassGroup.Notes = $Notes
            }

            if(Test-Bound -ParameterName 'Expires')
            {
                $KeePassGroup.Expires = $Expires
            }

            if($ExpiryTime)
            {
                $KeePassGroup.ExpiryTime = $ExpiryTime.ToUniversalTime()
            }

            $KeePassParentGroup.AddGroup($KeePassGroup, $true)
            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassGroup
            }
        }
    }
}

function ConvertFrom-KPProtectedString {
    <#
        .SYNOPSIS
            This Function will Convert a KeePass ProtectedString to Plain Text.
        .DESCRIPTION
            This Function will Convert a KeePassLib.Security.ProtectedString to Plain Text.

            This Would Primarily be used for Reading Title,UserName,Password,Notes, and URL ProtectedString Values.
        .EXAMPLE
            PS>Get-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 21 | ConvertFrom-KeePassProtectedString

            This Example will created a password using the specified options and convert the resulting password to a string.
        .PARAMETER KeePassProtectedString
            This is the KeePassLib.Security.ProtectedString to be converted to plain text
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()] [KeePassLib.Security.ProtectedString] $KeePassProtectedString
    )
    process
    {
        $KeePassProtectedString.ReadSafe()
    }
}

function Get-KPEntry {
    <#
        .SYNOPSIS
            This function will lookup and Return KeePass one or more KeePass Entries.
        .DESCRIPTION
            This function will lookup Return KeePass Entry(ies). It supports basic lookup filtering.
        .EXAMPLE
            PS> Get-KPEntryBase -KeePassConnection $DB -UserName "MyUser"

            This Example will return all entries that have the UserName "MyUser"
        .EXAMPLE
            PS> Get-KPEntry -KeePassConnection $DB -KeePassGroup $KpGroup

            This Example will return all entries that are in the specified group.
        .EXAMPLE
            PS> Get-KPEntry -KeePassConnection $DB -UserName "AUserName"

            This Example will return all entries have the UserName "AUserName"
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See New-KeePassConnection to Create the connection Object.
        .PARAMETER KeePassGroup
            This is the KeePass Group Object in which to search for entries.
        .PARAMETER Title
            This is a Title of one or more KeePass Entries.
        .PARAMETER UserName
            This is the UserName of one or more KeePass Entries.
        .PARAMETER KeePassUuid
            Specify the KeePass Entry Uuid for reverse lookup.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwEntry')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'UUID', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Uuid')]
        [KeePassLib.PwUuid] $KeePassUuid,

        [Parameter(Position = 2, ParameterSetName = 'Group')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Title')]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3, ParameterSetName = 'Group')]
        [Parameter(Position = 2, ParameterSetName = 'Title')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'UserName')]
        [ValidateNotNullOrEmpty()]
        [String] $UserName
    )
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            $KeePassItems = $KeePassConnection.RootGroup.GetEntries($true)

            if($PSCmdlet.ParameterSetName -eq 'UUID')
            {
                $KeePassItems | Where-Object { $KeePassUuid.CompareTo($_.Uuid) -eq 0 }
            }
            else
            {
                ## This a lame way of filtering.
                if($KeePassGroup)
                {
                    $KeePassItems = foreach($_keepassItem in $KeePassItems)
                    {
                        if($KeePassGroup.Contains($_keepassItem.ParentGroup))
                        {
                            $_keepassItem
                        }
                    }
                }

                if($Title)
                {
                    $KeePassItems = foreach($_keepassItem in $KeePassItems)
                    {
                        if($_keepassItem.Strings.ReadSafe('Title').ToLower().Equals($Title.ToLower()))
                        {
                            $_keepassItem
                        }
                    }
                }

                if($UserName)
                {
                    $KeePassItems = foreach($_keepassItem in $KeePassItems)
                    {
                        if($_keepassItem.Strings.ReadSafe('UserName').ToLower().Equals($UserName.ToLower()))
                        {
                            $_keepassItem
                        }
                    }
                }

                $KeePassItems
            }
        }
    }
}

function Get-KPGroup {
    <#
        .SYNOPSIS
            Gets a KeePass Group Object.
        .DESCRIPTION
            Gets a KeePass Group Object. Type: KeePassLib.PwGroup
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -FullPath 'full/KPDatabase/pathtoGroup'

            This Example will return a KeePassLib.PwGroup array Object with the full group path specified.
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -GroupName 'Test Group'

            This Example will return a KeePassLib.PwGroup array Object with the groups that have the specified name.
        .PARAMETER KeePassConnection
            Specify the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER FullPath
            Specify the FullPath of a Group or Groups in a KPDB
        .PARAMETER GroupName
            Specify the GroupName of a Group or Groups in a KPDB.
        .PARAMETER KeePassUuid
            Specify the Uuid of the Group.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwGroup')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Full')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Partial')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Full')]
        [ValidateNotNullOrEmpty()]
        [String] $FullPath,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Partial')]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2)]
        [Switch] $Stop
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup[]] $KeePassOutGroups = $null
            [KeePassLib.PwGroup[]] $KeePassGroups = $KeePassConnection.RootGroup
            $KeePassGroups += $KeePassConnection.RootGroup.GetFlatGroupList()
        }
        catch
        {
            Write-Warning -Message 'An error occured while getting a KeePassLib.PwGroup Object.'
            Write-Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            [int] $foundCount = 0

            if($PSCmdlet.ParameterSetName -eq 'Full')
            {
                foreach($_keepassGroup in $KeePassGroups)
                {
                    if($_keepassGroup.GetFullPath('/', $true).ToLower().Equals($FullPath.ToLower()))
                    {
                        $_keepassGroup
                        $foundCount += 1
                    }
                }
            }
            elseif($PSCmdlet.ParameterSetName -eq 'Partial')
            {
                foreach($_keepassGroup in $KeePassGroups)
                {
                    if($_keepassGroup.Name.ToLower().Equals($GroupName.ToLower()))
                    {
                        $_keepassGroup
                        $foundCount += 1
                    }
                }
            }
            elseif($PSCmdlet.ParameterSetName -eq 'None')
            {
                $KeePassGroups
                $foundCount = $KeePassGroups.Count
            }
        }

        if($Stop -and $foundCount -eq 0)
        {
            Write-Warning -Message ('[PROCESS] The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassGroupParentPath)
            Throw 'The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassGroupParentPath
        }
    }
}

function Get-KPPasswordProfile {
    <#
        .SYNOPSIS
            Function to Retreive All or a Specified Password Profile.
        .DESCRIPTION
            Function to Retreive All or a Specified Password Profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile Name to Retreive.
        .EXAMPLE
            PS> Get-KPPasswordProfile

            Returns all Password Profile definitions if any.
        .NOTES
            Internal Funciton.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    process
    {
        if(Test-Path -Path $Global:KeePassConfigurationFile)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($Global:KeePassConfigurationFile)

            if($PasswordProfileName)
            {
                $XML.Settings.PasswordProfiles.Profile | Where-Object { $_.Name -ilike $PasswordProfileName }
            }
            else
            {
                $XML.Settings.PasswordProfiles.Profile
            }
        }
        else
        {
            Write-Verbose 'No KeePass Configuration files exist, please create one to continue: New-KeePassDatabasConfiguration.'
        }
    }
}

function Import-KPLibrary {
    [CmdletBinding()]
    param()
    process
    {
        $Path = Resolve-Path $Global:KeePassLibraryPath
        Add-Type -Path $Path.Path
    }
}

function New-KPConfigurationFile {
    <#
        .SYNOPSIS
            This Internal Function Creates the KeePassConfiguration.xml file.
        .DESCRIPTION
            This Internal Function Creates the KeePassConfiguration.xml file.
            This File is used to store database configuration for file locations, authentication settings and password profiles.
        .PARAMETER Force
            Specify this parameter to forcefully overwrite the existing config with a new fresh config.
        .EXAMPLE
            PS> New-KPConfigurationFile

            This Example will create a new KeePassConfiguration.xml file.
        .NOTES
            Internal Function.
        .INPUTS
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [Switch] $Force
    )
    process
    {
        if((Test-Path -Path $Global:KeePassConfigurationFile) -and -not $Force)
        {
            Write-Warning -Message '[PROCESS] A KeePass Configuration File already exists. Please rerun with -force to overwrite the existing configuration.'
            Write-Error -Message 'A KeePass Configuration File already exists.' -ea Stop
        }
        else
        {
            try
            {
                $Path = $Global:KeePassConfigurationFile

                $XML = New-Object System.Xml.XmlTextWriter($Path, $null)
                $XML.Formatting = 'Indented'
                $XML.Indentation = 1
                $XML.IndentChar = "`t"
                $XML.WriteStartDocument()
                $XML.WriteProcessingInstruction('xml-stylesheet', "type='text/xsl' href='style.xsl'")
                $XML.WriteStartElement('Settings')
                $XML.WriteStartElement('DatabaseProfiles')
                $XML.WriteEndElement()
                $XML.WriteStartElement("PasswordProfiles")
                $XML.WriteEndElement()
                $XML.WriteEndElement()
                $XML.WriteEndDocument()
                $xml.Flush()
                $xml.Close()
            }
            catch
            {
                Write-Warning -Message 'An exception occured while trying to create a new keepass configuration file.'
                Write-Error -ErrorRecord $_ -ea Stop
            }
        }
    }
}

function New-KPConnection {
    <#
        .SYNOPSIS
            Creates an open connection to a Keepass database
        .DESCRIPTION
            Creates an open connection to a Keepass database using all available authentication methods
        .PARAMETER Database
            Path to the Keepass database (.kdbx file)
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

function New-KPPasswordProfile {
    <#
        .SYNOPSIS
            Function to save a password profile to the KeePassConfiguration.xml file.
        .DESCRIPTION
            This funciton will save a password profile to the config file.
            This is an internal function and is used in the -saveas option of the New-KeePassPassword function.
        .PARAMETER KeePassPasswordObject
            Specify the KeePass Password Profile Object to be saved to the config file.
        .EXAMPLE
            PS> New-KPPasswordProfile -KeePassPasswordObject $NewPasswordProfile

            This Example adds the $NewPasswordProfile object to the KeePassConfiguration.xml file.
        .NOTES
            Internal Funciton
        .INPUTS
            PSObject
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $KeePassPasswordObject
    )
    process
    {
        if(Test-Path -Path $Global:KeePassConfigurationFile)
        {
            $CheckIfExists = Get-KPPasswordProfile -PasswordProfileName $KeePassPasswordObject.ProfileName
            if($CheckIfExists)
            {
                Write-Warning -Message ('[PROCESS] A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName)
                Throw 'A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName
            }

            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($Global:KeePassConfigurationFile)
            ## Create New Profile Element with Name of the new profile
            $PasswordProfile = $XML.CreateElement('Profile')
            $PasswordProfileAtribute = $XML.CreateAttribute('Name')
            $PasswordProfileAtribute.Value = $KeePassPasswordObject.ProfileName
            $PasswordProfile.Attributes.Append($PasswordProfileAtribute) | Out-Null

            ## Build and Add Element Nodes
            $CharacterSetNode = $XML.CreateNode('element', 'CharacterSet', '')
            $CharacterSetNode.InnerText = $KeePassPasswordObject.CharacterSet
            $PasswordProfile.AppendChild($CharacterSetNode) | Out-Null

            $ExcludeLookAlikeNode = $XML.CreateNode('element', 'ExcludeLookAlike', '')
            $ExcludeLookAlikeNode.InnerText = $KeePassPasswordObject.ExcludeLookAlike
            $PasswordProfile.AppendChild($ExcludeLookAlikeNode) | Out-Null

            $NoRepeatingCharactersNode = $XML.CreateNode('element', 'NoRepeatingCharacters', '')
            $NoRepeatingCharactersNode.InnerText = $KeePassPasswordObject.NoRepeatingCharacters
            $PasswordProfile.AppendChild($NoRepeatingCharactersNode) | Out-Null

            $ExcludeCharactersNode = $XML.CreateNode('element', 'ExcludeCharacters', '')
            $ExcludeCharactersNode.InnerText = $KeePassPasswordObject.ExcludeCharacters
            $PasswordProfile.AppendChild($ExcludeCharactersNode) | Out-Null

            $LengthNode = $XML.CreateNode('element', 'Length', '')
            $LengthNode.InnerText = $KeePassPasswordObject.Length
            $PasswordProfile.AppendChild($LengthNode) | Out-Null

            $XML.SelectSingleNode('/Settings/PasswordProfiles').AppendChild($PasswordProfile) | Out-Null

            $XML.Save($Global:KeePassConfigurationFile)
        }
        else
        {
            Write-Output 'No KeePass Database Configuration file exists. You can create one with the New-KeePassDatabaseConfiguration function.'
        }
    }
}

function Remove-KPConnection {
    <#
        .SYNOPSIS
            This Function Removes a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Removes a Connection to a KeePass Database.
        .EXAMPLE
            PS> Remove-KPConnection -KeePassConnection $DB

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

function Remove-KPEntry {
    <#
        .SYNOPSIS
            Remove a Specific KeePass Entry.
        .DESCRIPTION
            Remove a Specified KeePass Database Entry.
         .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KPConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to be deleted.
        .PARAMETER NoRecycle
            Specify this flag to Permanently delete an entry. (ei skip the recycle bin)
        .PARAMETER Force
            Specify this flag to forcefully delete an entry.
        .EXAMPLE
            PS> Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KeePassEntryObject

            This Will remove a keepass database entry and prompt for confirmation.
        .INPUTS
            Strings
            KeePassLib.PwDatabase
            KeePassLib.PwEntry
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3)]
        [Switch] $Force
    )
    begin
    {
        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)

            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }

        $EntryDisplayName = "$($KeePassEntry.ParentGroup.GetFullPath('/', $true))/$($KeePassEntry.Strings.ReadSafe('Title'))"
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if($Force -or $PSCmdlet.ShouldProcess($($EntryDisplayName)))
            {
                if($RecycleBin -and -not $NoRecycle)
                {
                    ## Make Copy of the group to be recycled.
                    $DeletedKeePassEntry = $KeePassEntry.CloneDeep()
                    ## Generate a new Uuid and update the copy fo the group
                    $DeletedKeePassEntry.Uuid = (New-Object KeePassLib.PwUuid($true))
                    ## Add the copy to the recycle bin, with take ownership set to true
                    $RecycleBin.AddEntry($DeletedKeePassEntry, $true)
                    ## Save for safety
                    $KeePassConnection.Save($null)
                    ## Delete Original Entry
                    $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry) > $null
                    ## Save again
                    $KeePassConnection.Save($null)
                    Write-Verbose -Message "[PROCESS] Group has been Recycled."
                }
                else
                {
                    if($Force -or $PSCmdlet.ShouldContinue("Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.", "Do you want to continue to Permanently Delete this Entry: ($($EntryDisplayName))?"))
                    {
                        ## Deletes the specified group
                        $IsRemoved = $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry)

                        if(-not $IsRemoved)
                        {
                            Write-Warning -Message "[PROCESS] Unknown Error has occured. Failed to Remove Entry ($($EntryDisplayName))"
                            Throw "Failed to Remove Entry $($EntryDisplayName)"
                        }
                        else
                        {
                            Write-Verbose -Message "[PROCESS] Entry ($($EntryDisplayName)) has been Removed."
                            $KeePassConnection.Save($null)
                        }
                    }
                }
            }
        }
    }
}

function Remove-KPGroup {
    <#
        .SYNOPSIS
            Function to remove a KeePass Group
        .DESCRIPTION
            Function to remove a specified KeePass Group.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            Specify the Group to be removed.
        .PARAMETER NoRecycle
            Specify if you do not want the group to go to the Recycle Bin.
        .PARAMETER Force
            Specify to forcefully remove a group.
        .EXAMPLE
            PS> Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject

            Removes the specified account. Prompts before deletion and will put to recyclebin if there is one.
        .INPUTS
            KeePassLib.PwDatabase
            KeePassLib.PwGroup
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3)]
        [Switch] $Force
    )
    begin
    {
        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
            {
                if($RecycleBin -and -not $NoRecycle)
                {
                    ## Make Copy of the group to be recycled.
                    $DeletedKeePassGroup = $KeePassGroup.CloneDeep()
                    ## Generate a new Uuid and update the copy fo the group
                    $DeletedKeePassGroup.Uuid = (New-Object KeePassLib.PwUuid($true))
                    ## Add the copy to the recycle bin, with take ownership set to true
                    $RecycleBin.AddGroup($DeletedKeePassGroup, $true, $true)
                    $KeePassConnection.Save($null)
                    $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                    $KeePassConnection.Save($null)
                    Write-Verbose -Message '[PROCESS] Group has been Recycled.'
                }
                else
                {
                    if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Do you want to continue to Permanently Delete this Group: ($($KeePassGroup.GetFullPath('/', $true)))?"))
                    {
                        ## Deletes the specified group
                        $IsRemoved = $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup)
                        if(-not $IsRemoved)
                        {
                            Write-Warning -Message ('[PROCESS] Unknown Error has occured. Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true))
                            Throw 'Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true)
                        }
                        else
                        {
                            Write-Verbose -Message ('[PROCESS] Group ({0}) has been Removed.' -f $KeePassGroup.GetFullPath('/', $true))
                            $KeePassConnection.Save($null)
                        }
                    }
                }
            }
        }
    }
}

function Remove-KPPasswordProfile {
    <#
        .SYNOPSIS
            Function to remove a specifed Password Profile.
        .DESCRIPTION
            Removes a specified password profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile to be delete from the config file.
        .EXAMPLE
            PS> Remove-KPPasswordProfile -PasswordProfileName 'Personal'

            This example remove the password profile with the name 'Personal'
        .NOTES
            Internal Funciton.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    begin
    {
    }
    process
    {
        if(-not (Test-Path -Path $Global:KeePassConfigurationFile))
        {
            Write-Verbose -Message '[PROCESS] A KeePass Configuration File does not exist.'
        }
        else
        {
            if($PSCmdlet.ShouldProcess($PasswordProfileName))
            {
                try
                {
                    [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                    $XML.Load($Global:KeePassConfigurationFile)
                    $XML.Settings.PasswordProfiles.Profile  | Where-Object { $_.Name -eq $PasswordProfileName } | ForEach-Object { $xml.Settings.PasswordProfiles.RemoveChild($_) } | Out-Null
                    $XML.Save($Global:KeePassConfigurationFile)
                }
                catch [exception]
                {
                    Write-Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Password Profile ({0}).' -f $PasswordProfileName)
                    Write-Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                    Throw $_
                }
            }
        }
    }
}

function Restore-KPConfigurationFile {
    <#
        .SYNOPSIS
            Restore Config file from previous version
        .DESCRIPTION
            Restore Config file from previous version
        .PARAMETER
        .EXAMPLE
        .NOTES
        .INPUTS
        .OUTPUTS
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [String] $BreakingChangesVersion
    )
    process
    {
        $ReturnStatus = $false
        $Path = Resolve-Path -Path ('{0}\..' -f $PSScriptRoot)

        Write-Verbose -Message ('[PROCESS] Checking if there is a previous KeePassConfiguration.xml file to be loaded from: {0}.' -f $Path.Path )
        $PreviousVersion = ((Get-ChildItem $Path.Path).Name | Sort-Object -Descending | Select-Object -First 2)[1]

        Write-Verbose -Message ('PreviousVersion: {0}.' -f $PreviousVersion)
        $PreviousVersionConfigurationFile = Resolve-Path -Path ('{0}\..\{1}\KeePassConfiguration.xml' -f $PSScriptRoot, $PreviousVersion) -ErrorAction SilentlyContinue -ErrorVariable GetPreviousConfigurationFileError

        if(-not $GetPreviousConfigurationFileError -and $PreviousVersion)
        {
            Write-Verbose -Message ('[PROCESS] Copying last Configuration file from the previous version ({0}).' -f $PreviousVersion)
            Copy-Item -Path $PreviousVersionConfigurationFile -Destination "$PSScriptRoot" -ErrorAction SilentlyContinue -ErrorVariable RestorePreviousConfigurationFileError

            if($RestorePreviousConfigurationFileError)
            {
                Write-Warning -Message '[PROCESS] Unable to restore previous KeePassConfiguration.xml file. You will need to copy your previous file from your previous module version folder or create a new one.'
            }
            else
            {
                $ReturnStatus = $true
            }
        }

        return $ReturnStatus
    }
}

function Set-KPEntry {
    <#
        .SYNOPSIS
            This Function will update a entry.
        .DESCRIPTION
            This Function will update a entry.

            Currently This function supportes the basic fields for a KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to update/set atrributes.
        .PARAMETER KeePassGroup
            Specifiy this if you want Move the KeePassEntry to another Group
        .PARAMETER Title
            This is the Title to update/set.
        .PARAMETER UserName
            This is the UserName to update/set.
        .PARAMETER KeePassPassword
            This is the Password to update/set.
        .PARAMETER Notes
            This is the Notes to update/set.
        .PARAMETER URL
            This is the URL to update/set.
        .PARAMETER Tags
            Specify the Tags of the new KeePass Database Entry.
        .PARAMETER PassThru
            Returns the updated KeePass Entry after updating.
        .PARAMETER Force
            Specify to force updating the KeePass Entry.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2)]
        [String] $Title,

        [Parameter(Position = 3)]
        [String] $UserName,

        [Parameter(Position = 4)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [String] $URL,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 8)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 9)]
        [bool] $Expires,

        [Parameter(Position = 10)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 11)]
        [String[]] $Tags,

        [Parameter(Position = 12)]
        [Switch] $PassThru,

        [Parameter(Position = 13)]
        [Switch] $Force
    )
    process
    {
        if((Test-KPPasswordValue $KeePassPassword) -and (Test-KPConnection $KeePassConnection))
        {

            if($Force -or $PSCmdlet.ShouldProcess("Title: $($KeePassEntry.Strings.ReadSafe('Title')). `n`tUserName: $($KeePassEntry.Strings.ReadSafe('UserName')). `n`tGroup Path $($KeePassEntry.ParentGroup.GetFullPath('/', $true))"))
            {
                [KeePassLib.PwEntry] $OldEntry = $KeePassEntry.CloneDeep()

                if($Title)
                {
                    $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                    $KeePassEntry.Strings.Set('Title', $SecureTitle)
                }

                if($UserName)
                {
                    $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                    $KeePassEntry.Strings.Set('UserName', $SecureUser)
                }

                if($KeePassPassword)
                {
                    if($KeePassPassword.GetType().Name -eq 'SecureString')
                    {
                        $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                        $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                    }
                    elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                    {
                        $KeePassSecurePasswordString = $KeePassPassword
                    }
                    $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
                }

                if($Notes)
                {
                    $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                    $KeePassEntry.Strings.Set('Notes', $SecureNotes)
                }

                if($URL)
                {
                    $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                    $KeePassEntry.Strings.Set('URL', $SecureURL)
                }

                if($IconName -and $IconName -ne $KeePassEntry.IconId)
                {
                    $KeePassEntry.IconId = $IconName
                }

                if(Test-Bound -ParameterName 'Expires')
                {
                    $KeePassEntry.Expires = $Expires
                }

                if($ExpiryTime)
                {
                    $KeePassEntry.ExpiryTime = $ExpiryTime.ToUniversalTime()
                }

                if($Tags)
                {
                    $Tags | ForEach-Object { $null = $KeePassEntry.AddTag($_) }
                }

                $OldEntry.History.clear()
                $KeePassEntry.History.Add($OldEntry)

                if($KeePassGroup)
                {
                    $OldKeePassGroup = $KeePassEntry.ParentGroup
                    ## Add to group and move
                    $KeePassGroup.AddEntry($KeePassEntry, $true, $true)
                    ## delete old entry
                    $null = $OldKeePassGroup.Entries.Remove($KeePassEntry)
                }

                ## Add History Entry
                $KeePassEntry.LastModificationTime = [DateTime]::UtcNow
                $KeePassEntry.LastAccessTime = [DateTime]::UtcNow

                ## Save for safety
                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $KeePassEntry
                }
            }
        }
    }
}

function Set-KPGroup {
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER PassThru
            Specify to return the updated group object.
        .PARAMETER Force
            Specify to force updating the group.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2)]
        [String] $GroupName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 4)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [bool] $Expires,

        [Parameter(Position = 7)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 8)]
        [Switch] $PassThru,

        [Parameter(Position = 9)]
        [Switch] $Force
    )
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
            {
                if($GroupName)
                {
                    $KeePassGroup.Name = $GroupName
                }

                if($IconName -and $IconName -ne $KeePassGroup.IconId)
                {
                    $KeePassGroup.IconId = $IconName
                }

                if($Notes)
                {
                    $KeePassGroup.Notes = $Notes
                }

                if(Test-Bound -ParameterName 'Expires')
                {
                    $KeePassGroup.Expires = $Expires
                }

                if($ExpiryTime)
                {
                    $KeePassGroup.ExpiryTime = $ExpiryTime.ToUniversalTime()
                }

                if($KeePassParentGroup)
                {
                    if($KeePassGroup.ParentGroup.Uuid.CompareTo($KeePassParentGroup.Uuid) -ne 0 )
                    {
                        $UpdatedKeePassGroup = $KeePassGroup.CloneDeep()
                        $UpdatedKeePassGroup.Uuid = New-Object KeePassLib.PwUuid($true)
                        $KeePassParentGroup.AddGroup($UpdatedKeePassGroup, $true, $true)
                        $KeePassConnection.Save($null)
                        $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                        $KeePassConnection.Save($null)
                        $KeePassGroup = $UpdatedKeePassGroup
                    }
                }

                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $KeePassGroup
                }
            }
        }
    }
}

## Taken and Modified from DBATools
function Test-Bound {
    <#
        .SYNOPSIS
            Helperfunction that tests, whether a parameter was bound.

        .DESCRIPTION
            Helperfunction that tests, whether a parameter was bound.

        .PARAMETER ParameterName
            The name(s) of the parameter that is tested for being bound.
            By default, the check is true when AT LEAST one was bound.

        .PARAMETER Not
            Reverses the result. Returns true if NOT bound and false if bound.

        .PARAMETER And
            All specified parameters must be present, rather than at least one of them.

        .PARAMETER BoundParameters
            The hashtable of bound parameters. Is automatically inherited from the calling function via default value. Needs not be bound explicitly.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [string[]] $ParameterName,

        [Alias('Reverse')]
        [switch] $Not,

        [switch] $And,

        [object] $BoundParameters = (Get-PSCallStack)[0].InvocationInfo.BoundParameters
    )
    process
    {
        if($And)
        {
            $test = $true
        }
        else
        {
            $test = $false
        }

        foreach($name in $ParameterName)
        {
            if($And)
            {
                if(-not $BoundParameters.ContainsKey($name))
                {
                    $test = $false
                }
            }
            else
            {
                if($BoundParameters.ContainsKey($name))
                {
                    $test = $true
                }
            }
        }

        return ((-not $Not) -eq $test)
    }
}

function Test-KPConnection {
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [PSObject] $KeePassConnection
    )

    if($KeePassConnection.IsOpen)
    {
        $true
    }
    else
    {
        $false
        Write-Warning -Message 'The KeePass Connection Sepcified is not open or does not exist.'
        Write-Error -Message 'The KeePass Connection Sepcified is not open or does not exist.' -ea Stop
    }
}

function Test-KPPasswordValue {
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [PSObject] $KeePassPassword
    )

    if(-not $KeePassPassword)
    {
        $true
    }
    elseif($KeePassPassword.GetType().Name -eq 'SecureString')
    {
        $true
    }
    elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
    {
        $true
    }
    else
    {
        $false
        Write-Warning -Message '[PROCESS] Please provide a KeePassPassword of Type SecureString or KeePassLib.Security.ProtectedString.'
        Write-Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
        Write-Error -Message 'Please provide a KeePassPassword of Type SecureString or KeePassLib.Security.ProtectedString.' -ea Stop
    }
}

