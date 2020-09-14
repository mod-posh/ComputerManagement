---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-LocalUserAccounts.md#get-localuseraccounts
schema: 2.0.0
---

# Get-LocalUserAccounts

## SYNOPSIS
Return a list of local user accounts.

## SYNTAX

```
Get-LocalUserAccounts [[-ComputerName] <String>] [[-Credentials] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
This function returns the Name and SID of any local user accounts that are found
on the remote computer.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-LocalUserAccounts -ComputerName Desktop-PC01

  Name                                                      SID
  ----                                                      ---
  Administrator                                             S-1-5-21-1168524473-3979117187-4153115970-500
  Guest                                                     S-1-5-21-1168524473-3979117187-4153115970-501
```

This example shows the basic usage

### Example 2
```powershell
PS C:\> Get-LocalUserAccounts -ComputerName citadel -Credentials $Credentials

  Name                                                      SID
  ----                                                      ---
  Administrator                                             S-1-5-21-1168524473-3979117187-4153115970-500
  Guest                                                     S-1-5-21-1168524473-3979117187-4153115970-501
```

This example shows using the optional Credentials variable to pass administrator credentials

## PARAMETERS

### -ComputerName
The NetBIOS name of the remote computer

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credentials
Specifies a user account that has permission to perform this action. The default
value is the current user.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Object
## NOTES
You will need to provide credentials when running this against computers in a diffrent domain.

## RELATED LINKS
