<#PSScriptInfo

.VERSION 1.0

.GUID 60dfe24d-fc3e-4ac3-adc8-be00448e4159

.AUTHOR pardusurbanus@gmail.com

.COMPANYNAME 

.COPYRIGHT 

.TAGS 

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES

#>

<#
.DESCRIPTION
Name                           Value
----                           -----
PSVersion                      5.1.17763.1
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.17763.1
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
#>



function Write-Log{
  <#
  .SYNOPSIS
      Logging function.

  .DESCRIPTION
      Function is intend to write log to file and to the standart output.

  .PARAMETER LoggingPath
      Path to log file. 
      Defaults: creates log path with ".log" extension of file and name of current script.

  .PARAMETER Code
      Event code.
      Defaults: '0'.

  .PARAMETER Level
      Event severity level. May be 'Error','Warning' or 'Info'. 
      Defaults:'Info'.

  .PARAMETER Message
      Event message text. Mandatory parameter.

  .INPUTS
      Pipe takes string with event message text.

  .OUTPUTS
      Creates log file with header, if same named file does not exists. 
      Writes event string to file and writes message to console output. 
      Delimiter in file is ";" (file could be used as csv)

  .EXAMPLE
      Write-Log -Message "Something going wrong"
  #>
  [CmdletBinding()]
  Param ( 
      [Parameter(Mandatory=$false)] 
      [Alias('LogPath')] 
      [string]$LoggingPath=$("{0}/{1}.log" -f $PSScriptRoot, $(Get-Item $MyInvocation.ScriptName).BaseName),

      [Parameter(Mandatory=$false)] 
      [Alias('EventCode')] 
      [int]$Code=0,
          
      [Parameter(Mandatory=$false)] 
      [ValidateSet('Error','Warning','Info')] 
      [string]$Level="Info",
      
      [Parameter(Mandatory=$true,
              ValueFromPipeline=$true,
              ValueFromPipelineByPropertyName=$true)]
      [Alias('LogContent')]
      [string]$Message
  ) 
  process{
      [boolean]$isPathExist = Test-Path -Path $LoggingPath
      if(-not $isPathExist){
          $NewLogFile = New-Item $LoggingPath -Force -ItemType File
          "Date Time;Event Code;Event Level;Message" | Out-File -FilePath $NewLogFile.FullName -Append -Encoding utf8
          Write-Warning $("Log file was created in {0}" -f $NewLogFile.FullName)
      }    

      $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 

      switch ($Level) { 
          'Error' { 
              Write-Host "$Level : $Message" -ForegroundColor Red
              $LevelText = 'ERROR' 
              } 
          'Warning' { 
              Write-Host "$Level : $Message" -ForegroundColor Yellow
              $LevelText = 'WARNING' 
              } 
          'Info' { 
              Write-Host "$Level : $Message" -ForegroundColor Green
              $LevelText = 'INFO' 
              } 
          } 
          
      "$FormattedDate;$Code;$LevelText;$Message" | Out-File -FilePath $LoggingPath -Append -Encoding utf8
      "$FormattedDate;$Code;$LevelText;$Message`n"
  }
}

function New-LocalAdmin{
    <#
    .SYNOPSIS
        Adds user to admin group in ActiveDirectory.

    .DESCRIPTION
        Function is intend to add users to group, which will be use to store local admins on local machines. 
        Use ActiveDirectory cmdlets (included in RSAT). 
        Groups founds by DN, which specified in $GroupsOU variable.

    .PARAMETER Computer
        Computername (Name or CN). Mandatory.

    .PARAMETER ServiceRequest
        Number of service request or ticket. Mandatory.

    .PARAMETER User
        Username (samAccountName). Mandatory.

    .INPUTS
        Takes parameters above as a string.

    .OUTPUTS
        Creates local admin group if not exist.Adds user to the group. 
        Places info about previously added users to the group field "Info".

    .EXAMPLE
        New-LocalAdmin -Computer "comp21-01" -User "alex" -ServiceRequest "12345"
    #>
    Param (		
	    [Parameter(Mandatory=$True)]
	    [string]$Computer,

        [Parameter(Mandatory=$True)]
	    [string]$User,

        [Parameter(Mandatory=$True)]
	    [string]$ServiceRequest
    )
    process{

        $returnParams = @{
            Code = 0
            Message = ' '
            LogLevel = 'Info'		
        }

        $Group = "{0} Admins" -f $Computer.ToUpper()
        $InfoAttr = "Request #: {0}. User: {1}.`r`n" -f $ServiceRequest, $User
        $DescriptionAttr = "Members of this group belongs to local admins group of {0} machine." -f $Computer.ToUpper()

        #Where is groups located
        $GroupsOU = 'OU=PCLA,OU=Users group,DC=consoto,DC=dot,DC=com'

        try{
          #DOES USER EXISTS?
          if(Get-ADUser -Filter {samAccountName -eq $User}){
                #DOES COMPUTER EXISTS?
                if(Get-ADComputer -Filter {Name -eq $Computer -or CN -eq $Computer}){
                    #DOES GROUP EXISTS?
                    if(Get-ADGroup -Filter {SamAccountName -eq $Group}){
                        #IS USER ALREADY IN THE GROUP?
                        if($(Get-ADUser $User -Properties memberof).memberof.Contains(`
                                $(Get-ADGroup $Group -Properties DistinguishedName).DistinguishedName)){
                            $returnParams.Code = 1003
                            $returnParams.Level = 'Warning'
                            $returnParams.Message = "User {0} is already a member of the group {1}. No changes made." -f $User, $Group
                        }
                        else{
                            #Add member to the group
                            Add-ADGroupMember $Group $User

                            #Write Info field
                            $InfoStrings = $(Get-ADGroup $Group -Properties Info).Info
                            Set-ADGroup $Group -Replace @{info=$InfoStrings + $InfoAttr}

                            $returnParams.Code = 2001
                            $returnParams.Level = 'Info'
                            $returnParams.Message = "User {0} added to the group {1}" -f $User, $Group
                        }
        
                    }
                    else{
                        #Create if not
                        New-ADGroup -Name $Group -SamAccountName $Group `
                            -GroupCategory Security -GroupScope DomainLocal `
                            -DisplayName $Group -Path $GroupsOU `
                            -Description $DescriptionAttr -OtherAttributes @{info=$InfoAttr}

                        #Add member to the group
                        Add-ADGroupMember $Group $User

                        $returnParams.Code = 2002
                        $returnParams.Level = 'Info'
                        $returnParams.Message = "Group {0} created. User {1} added to the group." -f $Group, $User        
                    }  
              }
              else{
                  $returnParams.Code = 1002
                  $returnParams.Level = 'Error'
                  $returnParams.Message = "Computer {0} not found." -f $Computer
              }   
          }
          else{
              $returnParams.Code = 1001
              $returnParams.Level = 'Error'
              $returnParams.Message = "User {0} not found." -f $User
          }
        }
        catch{
          $returnParams.Code = 1004
          $returnParams.Level = 'Error'
          $returnParams.Message = "Error. Check the access rights or check AD module is loaded. You could reboot the script."
        }

        $returnParams
    }
}

function Remove-LocalAdmin{
    <#
    .SYNOPSIS
        Removes user from group in ActiveDirectory.

    .DESCRIPTION
        Function is intend to remove users from groups, that are used to store local admins on local machines. 
        Use ActiveDirectory cmdlets (included in RSAT). 

    .PARAMETER Computer
        Computername (Name or CN). Mandatory.

    .PARAMETER ServiceRequest номер
        Number of service request or ticket, on which user was added to admin group. Mandatory.

    .PARAMETER User
        Username (samAccountName). Mandatory.

    .INPUTS
        Takes parameters above as a string.

    .OUTPUTS
        Removes user from local admin group if user is member of it.

    .EXAMPLE
        Remove-LocalAdmin -Computer "comp21-01" -User "alex" -ServiceRequest "12345"
    #>
    Param (		
	    [Parameter(Mandatory=$True)]
	    [string]$Computer,

        [Parameter(Mandatory=$True)]
	    [string]$User,

        [Parameter(Mandatory=$True)]
	    [string]$ServiceRequest
    )
    process{

        $returnParams = @{
            Code = 0
            Message = ' '
            LogLevel = 'Info'		
        }

        $Group = $Computer.ToUpper() + ' Admins'
        $InfoAttr = "Request #{0}. User: {1}.`r`n" -f $ServiceRequest, $User
        try{
          #IS USER EXIST?
          if(Get-ADUser -Filter {samAccountName -eq $User}){
              #IS COMPUTER EXIST?
              if(Get-ADComputer -Filter {Name -eq $Computer -or CN -eq $Computer}){
                  #IS GROUP EXIST?
                  if(Get-ADGroup -Filter {SamAccountName -eq $Group}){
                      #IS USER A MEMBER OF THE GROUP?
                      if($(Get-ADUser $User -Properties memberof).memberof.Contains(`
                          $(Get-ADGroup $Group -Properties DistinguishedName).DistinguishedName)){
                              Remove-ADGroupMember $Group $User -Confirm:$false

                              #Rewrite Info fiels. Delete record about the ticket.
                              $InfoStrings = $(Get-ADGroup $Group -Properties Info).Info
                              $InfoStrings = $InfoStrings.Replace($InfoAttr, "`n")
                              Set-ADGroup $Group -Replace @{info=$InfoStrings}

                              $returnParams.Code = 2003
                              $returnParams.Level = 'Warning'
                              $returnParams.Message = "User {0} deleted from group {1}." -f $User, $Group
                      }
                      else{ 
                          $returnParams.Code = 1005
                          $returnParams.Level = 'Error'
                          $returnParams.Message = "User {0} is not a member of the group {1}" -f $User, $Group
                      }
                  }
                  else{
                      $returnParams.Code = 1006
                      $returnParams.Level = 'Error'
                      $returnParams.Message = "Group {0} not found." -f $Group   
                  }  
              }
              else{
                  $returnParams.Code = 1002
                  $returnParams.Level = 'Error'
                  $returnParams.Message = "Computer {0} not found." -f $Computer
              }   
          }
          else{
              $returnParams.Code = 1001
              $returnParams.Level = 'Error'
              $returnParams.Message = "User {0} not found." -f $User
          }
        }
        catch{
          $returnParams.Code = 1004
          $returnParams.Level = 'Error'
          $returnParams.Message = "Error. Check the access rights or check AD module is loaded. You could reboot the script."
        }

        $returnParams
    }
}



#Load ActiveDirectory module
Import-Module ActiveDirectory -NoClobber

#Load WinForm Assembley
[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

#Add form objects

$formAdmAdd = New-Object system.windows.forms.form
$formAdmAdd.width = 410
$formAdmAdd.height = 310
$formAdmAdd.Text = "Submitting or recall local admin rights"
$formAdmAdd.MaximizeBox = $false
$formAdmAdd.SizeGripStyle = "Show"
$formAdmAdd.FormBorderStyle = "FixedDialog"

$TextBoxUser = New-Object System.Windows.Forms.TextBox
$TextBoxUser.Location  = New-Object System.Drawing.Point(120,60)
$TextBoxUser.width = 265
$TextBoxUser.Text = 'User account name'

$TextBoxComputer = New-Object System.Windows.Forms.TextBox
$TextBoxComputer.Location  = New-Object System.Drawing.Point(120,90)
$TextBoxComputer.width = 265
$TextBoxComputer.Text = 'Computer name'

$TextBoxServiceRequest = New-Object System.Windows.Forms.TextBox
$TextBoxServiceRequest.Location  = New-Object System.Drawing.Point(120,120)
$TextBoxServiceRequest.width = 265
$TextBoxServiceRequest.Text = 'Ticket #'

$buttonCreate = New-Object System.Windows.Forms.Button
$buttonCreate.Text = 'Add'
$buttonCreate.Location = New-Object System.Drawing.Point(310,240)
#Handling click event
$buttonCreate.Add_Click({
    $reqMessage = "You will create administrator with parameters:`r`n`r`nUser: {0}`r`nComputer: {1}`r`nTicket #{2}" `
        -f $TextBoxUser.Text, $TextBoxComputer.Text, $TextBoxServiceRequest.Text

    $answerCode = [System.Windows.Forms.MessageBox]::Show($reqMessage , "Confirmation needed" , 4)

    if($answerCode -eq 'Yes'){
        $NewAdminCommand = New-LocalAdmin -User $TextBoxUser.Text `
            -Computer $TextBoxComputer.Text `
            -ServiceRequest $TextBoxServiceRequest.Text

        Write-Log -Code $NewAdminCommand.Code -Message $NewAdminCommand.Message -Level $NewAdminCommand.Level

        [System.Windows.Forms.MessageBox]::Show($NewAdminCommand.Message, $NewAdminCommand.Level, 0)

        if($NewAdminCommand.Code -eq 2001 -or $NewAdminCommand.Code -eq 2002){
            $TextBoxUser.Text = 'User account name'
            $TextBoxComputer.Text = 'Computer name'
            $TextBoxServiceRequest.Text = 'Ticket #'
        }
    }
})

$buttonDelete = New-Object System.Windows.Forms.Button
$buttonDelete.Text = 'Remove'
$buttonDelete.Location = New-Object System.Drawing.Point(220,240)
#Handling click event
$buttonDelete.Add_Click({
    $reqMessage = "Are you sure to remove user from admin group?`r`n`r`nUser: {0}`r`nComputer: {1}`r`nTicket #{2}" `
        -f $TextBoxUser.Text, $TextBoxComputer.Text, $TextBoxServiceRequest.Text
    $answerCode = [System.Windows.Forms.MessageBox]::Show($reqMessage , "Confirmation needed" , 4)

    if($answerCode -eq 'Yes'){
        $RemoveAdminCommand = Remove-LocalAdmin -User $TextBoxUser.Text `
            -Computer $TextBoxComputer.Text `
            -ServiceRequest $TextBoxServiceRequest.Text

        Write-Log -Code $RemoveAdminCommand.Code -Message $RemoveAdminCommand.Message -Level $RemoveAdminCommand.Level

        [System.Windows.Forms.MessageBox]::Show($RemoveAdminCommand.Message, $RemoveAdminCommand.Level, 0)

        if($RemoveAdminCommand.Code -eq 2003){
            $TextBoxUser.Text = 'User account name'
            $TextBoxComputer.Text = 'Computer name'
            $TextBoxServiceRequest.Text = 'Ticket #' 
        }
    }
})

$buttonCancel = New-Object System.Windows.Forms.Button
$buttonCancel.Text = 'Cancel'
$buttonCancel.Location = New-Object System.Drawing.Point(10,240)
$buttonCancel.Add_Click({[environment]::exit(0);$formAdmAdd.close()})

$Label_fio = New-Object System.Windows.Forms.Label
$Label_fio.Location = New-Object System.Drawing.Point(10,62)
$Label_fio.AutoSize = $true
$Label_fio.Text = 'Username:'

$Label_dep = New-Object System.Windows.Forms.Label
$Label_dep.Location = New-Object System.Drawing.Point(10,92)
$Label_dep.AutoSize = $true
$Label_dep.Text = 'Computername:'

$Label_job = New-Object System.Windows.Forms.Label
$Label_job.Location = New-Object System.Drawing.Point(10,122)
$Label_job.AutoSize = $true
$Label_job.Text = 'Ticket #:'

$Label_crt = New-Object System.Windows.Forms.Label
$Label_crt.Location = New-Object System.Drawing.Point(10,10)
$Label_crt.AutoSize = $true
$Label_crt.Text = 'Enter ticket data'

$line2 = New-Object System.Windows.Forms.Label
$line2.Location = New-Object System.Drawing.Point(10,220)
$line2.AutoSize = $false;
$line2.Height = 2;
$line2.Width = 375;
$line2.BorderStyle = "Fixed3D";

$line1 = New-Object System.Windows.Forms.Label
$line1.Location = New-Object System.Drawing.Point(10,40)
$line1.AutoSize = $false;
$line1.Height = 2;
$line1.Width = 375;
$line1.BorderStyle = "Fixed3D";

$formAdmAdd.Controls.Add($TextBoxUser)
$formAdmAdd.Controls.Add($TextBoxComputer)
$formAdmAdd.Controls.Add($TextBoxServiceRequest)
$formAdmAdd.Controls.Add($CheckBoxDeleteLocalAdmins)
$formAdmAdd.Controls.Add($buttonCreate)
$formAdmAdd.Controls.Add($buttonDelete)
$formAdmAdd.Controls.Add($Label_dep)
$formAdmAdd.Controls.Add($Label_fio)
$formAdmAdd.Controls.Add($Label_job)
$formAdmAdd.Controls.Add($Label_crt)
$formAdmAdd.Controls.Add($Lable_delLocAdm)
$formAdmAdd.Controls.Add($line2)
$formAdmAdd.Controls.Add($line1)
$formAdmAdd.Controls.Add($buttonCancel)

$formAdmAdd.ShowDialog()