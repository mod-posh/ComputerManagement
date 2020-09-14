---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#New-ScheduledTask
schema: 2.0.0
---

# New-ScheduledTask

## SYNOPSIS
Create a Scheduled Task on a computer.

## SYNTAX

```
New-ScheduledTask [-TaskName] <String> [-TaskRun] <String> [-TaskSchedule] <String> [-StartTime] <String>
 [-StartDate] <String> [-TaskUser] <String> [-Server] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Create a Scheduled Task on a local or remote computer.

## EXAMPLES

### EXAMPLE 1
```
New-ScheduledTask -TaskName "Reboot Computer" -TaskRun "shutdown /r" -TaskSchedule ONCE `
      -StartTime "18:00:00" -StartDate "03/16/2011" -TaskUser SYSTEM -Server MyDesktopPC
```

## PARAMETERS

### -Server
The NetBIOS name of the computer to create the scheduled task on.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartDate
Specifies the date that the task starts in MM/DD/YYYY format.
The
default value is the current date.
The /sd parameter is valid with all
schedules, and is required for a ONCE schedule.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartTime
Specifies the time of day that the task starts in HH:MM:SS 24-hour
format.
The default value is the current local time when the command
completes.
The /st parameter is valid with MINUTE, HOURLY, DAILY,
WEEKLY, MONTHLY, and ONCE schedules.
It is required with a ONCE
schedule.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TaskName
Specifies a name for the task.

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

### -TaskRun
Specifies the program or command that the task runs.
Type
the fully qualified path and file name of an executable file,
script file, or batch file.
If you omit the path, SchTasks.exe
assumes that the file is in the Systemroot\System32 directory.

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

### -TaskSchedule
Specifies the schedule type.
Valid values are
	MINUTE
	HOURLY
	DAILY
	WEEKLY
	MONTHLY
	ONCE
	ONSTART
	ONLOGON
	ONIDLE

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

### -TaskUser
Runs the tasks with the permission of the specified user account.
By
default, the task runs with the permissions of the user logged on to the
computer running SchTasks.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
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
The full syntax of the command can be found here:
	http://technet.microsoft.com/en-us/library/bb490996.aspx

## RELATED LINKS

[https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#New-ScheduledTask](https://github.com/jeffpatton1971/mod-posh/wiki/ComputerManagement#New-ScheduledTask)

