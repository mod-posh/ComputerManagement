---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-NonStandardServiceAccount.md#get-nonstandardserviceaccount
schema: 2.0.0
---

# Get-NonStandardServiceAccount

## SYNOPSIS
Return a list of services using Non-Standard accounts.

## SYNTAX

```
Get-NonStandardServiceAccount [[-Computer] <String>] [[-Credentials] <PSCredential>] [[-Filter] <String>]
 [<CommonParameters>]
```

## DESCRIPTION
This function returns a list of services from local or remote coputers that have
non-standard user accounts for logon credentials.

## EXAMPLES

### EXAMPLE 1
```
Get-NonStandardServiceAccounts

StartName                         Name                             DisplayName
---------                         ----                             -----------
.\Jeff Patton                     MyService                        My Test Service
```

This example shows no parameters provided

### EXAMPLE 2
```
Get-NonStandardServiceAccounts -Computer dpm -Credentials $Credentials

StartName                         Name                             DisplayName
---------                         ----                             -----------
.\MICROSOFT$DPM$Acct              MSSQL$MS$DPM2007$                SQL Server (MS$DPM2007$)
.\MICROSOFT$DPM$Acct              MSSQL$MSDPM2010                  SQL Server (MSDPM2010)
NT AUTHORITY\NETWORK SERVICE      MSSQLServerADHelper100           SQL Active Directory Helper S...
NT AUTHORITY\NETWORK SERVICE      ReportServer$MSDPM2010           SQL Server Reporting Services...
.\MICROSOFT$DPM$Acct              SQLAgent$MS$DPM2007$             SQL Server Agent (MS$DPM2007$)
.\MICROSOFT$DPM$Acct              SQLAgent$MSDPM2010               SQL Server Agent (MSDPM2010)
```

This example shows all parameters in use

### EXAMPLE 3
```
Get-NonStandardServiceAccounts -Computer dpm -Credentials $Credentials `
-Filter "localsystem|NT Authority\LocalService|NT Authority\NetworkService|NT AUTHORITY\NETWORK SERVICE"

StartName                         Name                             DisplayName
---------                         ----                             -----------
.\MICROSOFT$DPM$Acct              MSSQL$MS$DPM2007$                SQL Server (MS$DPM2007$)
.\MICROSOFT$DPM$Acct              MSSQL$MSDPM2010                  SQL Server (MSDPM2010)
.\MICROSOFT$DPM$Acct              SQLAgent$MS$DPM2007$             SQL Server Agent (MS$DPM2007$)
.\MICROSOFT$DPM$Acct              SQLAgent$MSDPM2010               SQL Server Agent (MSDPM2010)
```

This example uses the Filter parameter to filter out NT AUTHORITY\NETWORK SERVICE account from the
preceeding example.

The back-tick (\`) was used for readability purposes only.

## PARAMETERS

### -Computer
The NetBIOS name of the computer to pull services from.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: (& hostname)
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credentials
The DOMAIN\USERNAME of an account with permissions to access services.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Filter
This is a pipe (|) seperated list of accounts to filter out of the returned services list.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: Localsystem|NT Authority\LocalService|NT Authority\NetworkService
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Powershell may need to be run elevated to run this script. UAC may need to be
disabled to run this script.

## RELATED LINKS
