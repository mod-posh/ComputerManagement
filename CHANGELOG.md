# Changelog
All changes to this module should be reflected in this document.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
- Update module for current PowerShell

## [1.1.2.0] - 2020-09-14
### Removed
- Issue #55 Remove New-ScheduledTask

## [1.1.1.0] - 2020-09-14
### Removed
- Issue #43 Remove Add-LocalUserToGroup
- Issue #44 Remove Get-LocalUserAccounts
- Issue #45 Remove New-LocalUser
- Issue #46 Remove Remove-LocalUser
- Issue #50 Remove Remove-UserFromLocalGroup

## [1.1.0.0] - 2020-09-14
### Added
- Added Updatable help

### Updated
- Issue #37 Updated documentation help files
- Issue #38 Updatable help

## [1.0.0.0] - 2020-09-13
### Added
- Creating help
- Included build pipeline

### Updated
- Issue #15 Adding ShouldProcess to functions
- Issue #31 Updated OutputType
- Issue #30 Used full AclObject parameter
- Issue #29 Reduce/Remove invoke-expression
- Issue #5 Replace WMI with CIM cmdlets

## [1.0.0.0] - 2020-09-12
### Added
- Created ComputerManagement repository in mod-posh Organization
- Imported the original ComputerManagement module from the mod-posh repository

### Updated
- Issue #1 Removed Trailing whitespace
- Issue #9 Corrected empty Try/Catch block
- Issue #7 Set Output Type properly
- Issue #2 Removed default values for Mandatory parameters
- Issue #14 Removed unused parameters
- Issue #4 Removed Get-UpTime as it's built-in now
- Issue #13 Proper evaluation of $null
- Issue #6 Changed to proper verbs
- Issue #12 Use SecureString for Credentials/Passwords
- Issue #11 Construct SecureString