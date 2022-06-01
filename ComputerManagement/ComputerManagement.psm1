# Dot source public/private functions
$dotSourceParams = @{
 Filter      = '*.ps1'
 Recurse     = $true
 ErrorAction = 'Stop'
}
$public = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'public') @dotSourceParams )
$private = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'private/*.ps1') @dotSourceParams)
foreach ($import in @($public + $private)) {
 try {
  . $import.FullName
 }
 catch {
  throw "Unable to dot source [$($import.FullName)]"
 }
}