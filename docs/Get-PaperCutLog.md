---
external help file: ComputerManagement-help.xml
Module Name: ComputerManagement
online version: https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PaperCutLog.md#get-papercutlog
schema: 2.0.0
---

# Get-PaperCutLog

## SYNOPSIS
Get PaperCut logs from all print servers

## SYNTAX

```
Get-PaperCutLogs [[-PrintServers] <Object>] [<CommonParameters>]
```

## DESCRIPTION
Return the PaperCut logs from all print servers.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-PaperCutLogs |Export-Csv -Path .\PrintLog.csv
```

This example shows the basic usage of the command. The output is piped into
a spreadsheet on the local computer for further analysis.

## PARAMETERS

### -PrintServers
The FQDN of the print servers

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
You must have downlaoded and installed the latest version of PaperCut Print Logger for this to work.

http://www.papercut.com/products/free_software/print_logger/#

The resulting data will encompass all months that the servers have been logging data for, currently this goes back about 3 years. The CSV output can be opened in Excel and you can generate graphs based on which printer is used the most, how much paper is consumed by each printer and so on.

## OUTPUTS

### System.Object[]
## NOTES

## RELATED LINKS
