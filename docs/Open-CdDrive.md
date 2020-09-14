---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Open-CdDrive.md#open-cddrive
schema: 2.0.0
---

# Open-CdDrive

## SYNOPSIS
A function to eject the CD Drive

## SYNTAX

```
Open-CdDrive [[-Drive] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function uses the shell.application comObject to
eject one or more CD rom drives.
I had the need to eject several CDroms
from servers and wanted an easier way to do it.
I found a sample
in the Technet gallery (see link) and modified to suite my
needs.

## EXAMPLES

### EXAMPLE 1
```
Open-CdDrive

Application  : System.__ComObject
Parent       : System.__ComObject
Name         : DVD RW Drive (E:)
Path         : E:\
GetLink      :
GetFolder    : System.__ComObject
IsLink       : False
IsFolder     : True
IsFileSystem : True
IsBrowsable  : False
ModifyDate   : 12/30/1899 12:00:00 AM
Size         : 0
Type         : CD Drive
```

This example shows how to eject any cdrom on the system

### EXAMPLE 2
```
Open-CdDrive -Drive E:

Application  : System.__ComObject
Parent       : System.__ComObject
Name         : DVD RW Drive (E:)
Path         : E:\
GetLink      :
GetFolder    : System.__ComObject
IsLink       : False
IsFolder     : True
IsFileSystem : True
IsBrowsable  : False
ModifyDate   : 12/30/1899 12:00:00 AM
Size         : 0
Type         : CD Drive
```

This example shows how to eject the CD labled E: from the system

## PARAMETERS

### -Drive
If present it will eject the drive corresponding to the drive letter

```yaml
Type: System.String
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

## OUTPUTS

## NOTES
FunctionName : Open-CdDrive
Created by   : Jeffrey
Date Coded   : 01/10/2015 08:33:30

## RELATED LINKS


[Technet Gallery](https://gallery.technet.microsoft.com/scriptcenter/7d81af29-1cae-4dbb-8027-cd96a985f311)

