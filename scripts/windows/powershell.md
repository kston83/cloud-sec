# One Liners and stuff


**List Updates**
Use for listing installed KBs and verifying updates have been installed

`Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, InstalledOn | Format-Table -AutoSize`
