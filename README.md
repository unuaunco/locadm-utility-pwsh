# Local Admin Management Utility

The project uses PowerShell for entire logic and WPF (XAML) for user interface.

File `New-ClassicADForm.ps1` shows how to create this application through classic ".Net-style" form constructions.

File `New-WPFADForm.ps1` shows extended functional with XAML used to draw forms.

Each function has a description about using it.

Logic:

* ActiveDirectory Groups with name like "%COMPUTERNAME Admins" with user in it.
* Group Policy that searches group for computer in domain and place group to its local "Administrators" group. This works when computer updates its policy.
* User interface based on PowerShell and WPF(XAML) that uses by the manager to create groups, add or remove user from group and form a message and log about operation.

There are several functions in script:

* "Write-Log" - just write log of program operations.
* "New-LocalAdmin" - add user to "%COMPUTERNAME Admins" group (creates it if doesn`t exist).
* "Remove-LocalAdmin" - remove user from "%COMPUTERNAME Admins" group.
* "New-AdminGroup" - creates "%COMPUTERNAME Admins" group if doesn`t exist.
* "Get-AdminGroupMembers" - show list of users in "%COMPUTERNAME Admins" group.

You can use it like a script or convert it into .exe file by the special utility. My recommendation is "PS2EXE": [PS2EXE : "Convert" PowerShell Scripts to EXE Files](https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-Convert-PowerShell-9e4e07f1)