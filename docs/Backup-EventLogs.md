---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Backup-EventLogs.md#backup-eventlogs
schema: 2.0.0
---

# Backup-EventLogs

## SYNOPSIS
Backup Eventlogs from remote computer

## SYNTAX

```
Backup-EventLogs [[-ComputerName] <String>] [[-LogPath] <String>] [[-BackupPath] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function copies event log files from a remote computer to a backup location.

## EXAMPLES

### EXAMPLE 1
```
Backup-EventLogs -ComputerName dc1
```

## PARAMETERS

### -BackupPath
The location to copy the logs to.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: C:\Logs
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
The NetBIOS name of the computer to connect to.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogPath
The path to the logs you wish to backup. The default logpath
"C:\Windows\system32\winevt\Logs" is used if left blank.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: C:\Windows\system32\winevt\Logs
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
May need to be a user with rights to access various logs, such as security on remote computer.

## RELATED LINKS
