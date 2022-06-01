Function Get-PendingUpdate {
 [CmdletBinding(HelpURI = 'https://github.com/mod-posh/ComputerManagement/blob/master/docs/Get-PendingUpdate.md#get-pendingupdate')]
 Param
 (
  [Parameter(ValueFromPipeline = $True)]
  [string]$ComputerName
 )
 Begin {
 }
 Process {
  ForEach ($Computer in $ComputerName) {
   If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
    Try {
     $Updates = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session", $Computer))
     $Searcher = $Updates.CreateUpdateSearcher()
     $searchresult = $Searcher.Search("IsInstalled=0")
    }
    Catch {
     Write-Warning "$($Error[0])"
     Break
    }
   }
  }
 }
 End {
  Return $SearchResult.Updates
 }
}