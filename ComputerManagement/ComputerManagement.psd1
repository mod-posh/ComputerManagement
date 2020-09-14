#
# Module manifest for module 'PSGet_ComputerManagement'
#
# Generated by: Jeffrey Patton
#
# Generated on: 9/14/2020
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'ComputerManagement.psm1'

# Version number of this module.
ModuleVersion = '1.1.1.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '9c9c5339-5b88-4f63-a664-d9bf90b7ed3a'

# Author of this module
Author = 'Jeffrey Patton'

# Company or vendor of this module
CompanyName = 'Patton-Tech.com'

# Copyright statement for this module
Copyright = '9/12/2020 4:02:47 PM'

# Description of the functionality provided by this module
Description = 'A PowerShell module for working with the local computer'

# Minimum version of the Windows PowerShell engine required by this module
# PowerShellVersion = ''

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Set-Pass', 'New-ScheduledTask', 'Get-CimService', 
               'Get-NonStandardServiceAccount', 'Get-PendingUpdates', 
               'Get-ServiceTag', 'Backup-EventLogs', 'Export-EventLog', 
               'Get-PaperCutLogs', 'Set-ShutdownMethod', 'Get-PrinterLogs', 
               'Get-OpenSessions', 'Get-OpenFiles', 'Get-RDPLoginEvents', 
               'Get-InvalidLogonAttempts', 'Get-MappedDrives', 'Get-DiskUsage', 
               'Get-Namespace', 'New-Password', 'Connect-Rdp', 'Get-NetShare', 
               'Get-WinEventTail', 'Open-CdDrive', 'Grant-RegistryPermission', 
               'New-Credential'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/mod-posh/ComputerManagement/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/mod-posh'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = 'https://github.com/mod-posh/ComputerManagement/blob/master/CHANGELOG.md'

        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://raw.githubusercontent.com/mod-posh/ComputerManagement/master/cabs/'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

