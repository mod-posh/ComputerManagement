Function Get-DiskUsage {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-DiskUsage.md#get-diskusage')]
 Param
 (
  [string]$Path = "."
 )
 Begin {
 }
 Process {
  foreach ($Folder in (Get-ChildItem $Path)) {
   $ErrorActionPreference = "SilentlyContinue"
   try {
    $FolderSize = Get-ChildItem -Recurse $Folder.FullName | Measure-Object -Property Length -Sum
    if ($null -eq $FolderSize) {
     Write-Verbose $Error[0].ToString()
     $FolderSize = 0
    }
    else {
     $FolderSize = $FolderSize.sum
    }
   }
   catch {
    throw $_;
   }
   New-Object -TypeName PSobject -Property @{
    FolderName = $Folder.FullName
    FolderSize = $FolderSize
   }
  }
 }
 End {
 }
}