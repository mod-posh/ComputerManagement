---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Add-LocalUserToGroup.md#add-localusertogroup
schema: 2.0.0
---

# Add-LocalUserToGroup

## SYNOPSIS
Add an existing user to a local group.

## SYNTAX

```
Add-LocalUserToGroup [-ComputerName] <String> [-User] <String> [-Group] <String> [<CommonParameters>]
```

## DESCRIPTION
This function will add an existing user to an existing group.

## EXAMPLES

### EXAMPLE 1
```
Add-LocalUserToGroup -ComputerName MyComputer -User MyUserAccount -Group Administrators
```

## PARAMETERS

### -ComputerName
The NetBIOS name of the computer that you will add the account to.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Group
The name of an existing group to add this user to.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -User
The user name of the account that will be created.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
You will need to run this with either UAC disabled or from an elevated prompt.

## RELATED LINKS

