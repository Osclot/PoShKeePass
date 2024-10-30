## Import Functions
. "$PSScriptRoot\PoShKeePassInternal.ps1"
. "$PSScriptRoot\PoShKeePassFunctions.ps1"


[String] $Global:KeePassConfigurationFile = '{0}\KeePassConfiguration.xml' -f $PSScriptRoot
[String] $Global:KeePassLibraryPath = '{0}\bin\KeePassLib_2.55.dll' -f $PSScriptRoot

## Source KpLib
Import-KPLibrary

## Check for config and init
if (-not(Test-Path -Path $Global:KeePassConfigurationFile)) {
    if (-not $(Restore-KPConfigurationFile)) {
        New-KPConfigurationFile
    }
}
else {
    New-Variable -Name 'KeePassProfileNames' -Value @((Get-KeePassDatabaseConfiguration).Name) -Scope 'Script' #-Option Constant
}

#Export-ModuleMember *

if(Get-Command Register-ArgumentCompleter -ea 0) {
    Register-ArgumentCompleter -ParameterName 'DatabaseProfileName' -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

        Get-KeePassDatabaseConfiguration | Where-Object { $_.Name -ilike "${wordToComplete}*" } | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult ( $_.Name, $_.Name, 'ParameterValue', $_.Name)
        }
    }

    Register-ArgumentCompleter -ParameterName 'IconName' -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

        [KeePassLib.PwIcon].GetEnumValues() | Where-Object { $_ -ilike "${wordToComplete}*" } | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult ( $_, $_, 'ParameterValue', $_)
        }
    }

    Register-ArgumentCompleter -ParameterName 'PasswordProfileName' -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

        (Get-KPPasswordProfile).Name | Where-Object { $_ -ilike "${wordToComplete}*" } | ForEach-Object {
            New-Object System.Management.Automation.CompletionResult ( $_, $_, 'ParameterValue', $_)
        }
    }
}

## add one for paths - can't do this until connection management is implemented.
