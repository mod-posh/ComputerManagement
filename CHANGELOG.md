# Changelog
All changes to this module should be reflected in this document.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
- Add external help
- Update module for current PowerShell
- Fix issues uncovered by ScriptAnalyzer

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

## [1.0.0.0] - 2020-09-13
### Updated
- Issue #15 Adding ShouldProcess to functions
- Issue #31 Updated OutputType
- Issue #30 Used full AclObject parameter