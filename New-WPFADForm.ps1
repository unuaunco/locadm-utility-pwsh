<#PSScriptInfo

.VERSION 1.0

.GUID 60dfe24d-fc3e-4ac3-adc8-be00448e4160

.AUTHOR pardusurbanus@protonmail.com

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

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

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

function New-AdminGroup{
    <#
    .SYNOPSIS
        Creates new group in ActiveDirectory.

    .DESCRIPTION
        Function is intend to create groups, that are used to storage Admins of local machines.
        Use ActiveDirectory cmdlets (included in RSAT). 

    .PARAMETER Computer
        Computername (Name or CN). Mandatory.

    .INPUTS
        Takes parameters above as a string.

    .OUTPUTS
        Creates group named as a computer.

    .EXAMPLE
        New-AdminGroup -Computer "comp21-01"
    #>
    Param (		
	    [Parameter(Mandatory=$True)]
	    [string]$Computer
    )
    process{

        $returnParams = @{
            Code = 0
            Message = ' '
            LogLevel = 'Info'		
        }

        $Group = "{0} Admins" -f $Computer.ToUpper()
        $InfoAttr = "Request #{0}. User: {1}.`r`n" -f $ServiceRequest, $User
        $DescriptionAttr = "Members of this group belongs to local admins group of {0} machine." -f $Computer.ToUpper()

        try{
            #DOES THE COMPUTER EXISTS?
            if(Get-ADComputer -Filter {Name -eq $Computer -or CN -eq $Computer}){
                #DOES THE GROUP EXISTS?
                if(Get-ADGroup -Filter {SamAccountName -eq $Group}){
                    $returnParams.Code = 1007
                    $returnParams.Message = "Group {0} already exists." -f $Group
			        $returnParams.LogLevel = 'Warning'
                }
                else{
                    #Create if not
                    New-ADGroup -Name $Group -SamAccountName $Group -GroupCategory Security `
                        -GroupScope DomainLocal -DisplayName $Group `
                        -Path $GroupsOU -Description $DescriptionAttr
                    $returnParams.Code = 2004
                    $returnParams.Message = "Group {0} created successfully." -f $Group
                    $returnParams.LogLevel = 'Info'
                }  
            }
            else{
                $returnParams.Code = 1002
                $returnParams.Level = 'Error'
                $returnParams.Message = "Computer {0} not found." -f $Computer
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

function Get-AdminGroupMembers{
    <#
    .SYNOPSIS
        Prints list of users in ActiveDirectory group.

    .DESCRIPTION
        Function intend to print list of users, which are Admins of local machines.
        Use ActiveDirectory cmdlets (included in RSAT). 

    .PARAMETER Computer
        Computername (Name or CN). Mandatory.

    .INPUTS
        Takes parameters above as string.

    .OUTPUTS
        Prints user list, which are members of the group.

    .EXAMPLE
        Get-AdminGroupMembers -Computer "comp21-01"
    #>
    Param (		
	    [Parameter(Mandatory=$True)]
	    [string]$Computer
    )
    process{

        $returnParams = @{
            Code = 0
            Message = ' '
            LogLevel = 'Info'		
        }

        $Group = "{0} Admins" -f $Computer.ToUpper()
        $userList = ''

        try{
            #DOES THE COMPUTER EXISTS?
            if(Get-ADComputer -Filter {Name -eq $Computer -or CN -eq $Computer}){
                #DOES THE GROUP EXISTS?
                if(Get-ADGroup -Filter {SamAccountName -eq $Group}){
                    $GroupMembers = Get-ADGroupMember -Identity $Group
                    if($GroupMembers){
                        foreach($Member in $Groupmembers){
                            $userList += "{0}, " -f $Member.SamAccountName
                        }
                        $returnParams.Code = 2005
                        $returnParams.Message = "Group {0} contains next users: {1}" -f $Group, $userList.TrimEnd(', ')
			            $returnParams.LogLevel = 'Info'
                    }
                    else{
                        $returnParams.Code = 1008
                        $returnParams.Message = "Group {0} does not contains any users" -f $Group
			            $returnParams.LogLevel = 'Info'
                    }
                }
                else{
                    $returnParams.Code = 1006
                    $returnParams.Message = "Group {0} not found." -f $Group
			        $returnParams.LogLevel = 'Warning'                    
                }  
            }
            else{
                $returnParams.Code = 1002
                $returnParams.Level = 'Error'
                $returnParams.Message = "Computer {0} not found." -f $Computer
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

$returnParams = @{
    Code = 0
    Message = ' '
    LogLevel = 'Info'		
}

$global:ProgressPreference='SilentlyContinue'

#Import ActiveDirectory module
Import-Module ActiveDirectory -NoClobber

#===========================================================================
# XAML Code - Imported from Visual Studio Express 2013 WPF Application
# Contains all needed elements and markup
#===========================================================================
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = @'
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
		Title="CFT Local Admin Management" Height="645.714" Width="500" ResizeMode="CanMinimize" Left="0" Top="0" WindowStartupLocation="CenterScreen" SizeToContent="WidthAndHeight">
		<Grid Width="492" Margin="0">
			<TabControl HorizontalAlignment="Left" Height="384" Margin="10,10,0,0" VerticalAlignment="Top" Width="472">
				<TabItem Name="addRights_tab" Header="Add rights" Background="#FFC2C6C8" Height="22">
					<Grid Width="466" Margin="0,10,0,2" Height="342">
						<Grid.ColumnDefinitions>
							<ColumnDefinition Width="131*"/>
							<ColumnDefinition Width="102*"/>
						</Grid.ColumnDefinitions>
						<Label Name="header_label1" Content="Write ticket data" HorizontalAlignment="Left" Margin="10,2,0,0" VerticalAlignment="Top" Height="30" Width="446" Background="#FFC2C6C8" Foreground="White" HorizontalContentAlignment="Center" VerticalContentAlignment="Center" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="userName_label1" Content="Username" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="computerName_label1" Content="ComputerName" HorizontalAlignment="Left" Margin="10,143,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="sdRequest_label1" Content="Ticket number" HorizontalAlignment="Left" Margin="10,233,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True" Grid.ColumnSpan="2"/>
						<TextBox Name="userName_textBox1" HorizontalAlignment="Left" Height="30" Margin="10,91,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center" Grid.ColumnSpan="2"/>
						<TextBox Name="computerName_textBox1" HorizontalAlignment="Left" Height="30" Margin="10,178,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center" Grid.ColumnSpan="2" Background="White"/>
						<TextBox Name="sdRequest_textBox1" HorizontalAlignment="Left" Height="30" Margin="10,268,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center" Grid.ColumnSpan="2"/>
						<Button Name="addRights_button" Content="Add" HorizontalAlignment="Left" Height="32" Margin="80,303,0,0" VerticalAlignment="Top" Width="114" Background="#FFDDDDDD" BorderBrush="{x:Null}" Grid.Column="1"/>
						<TextBlock Name="userName_textBlock1" IsHitTestVisible="False" Text="Write user name e.g. alex" VerticalAlignment="Top" HorizontalAlignment="Left" Margin="15,96,0,0" Foreground="DarkGray" Width="440" Height="20" Grid.ColumnSpan="2">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=userName_textBox1}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style>
						</TextBlock>
						<TextBlock Name="computerName_textBlock1" IsHitTestVisible="False" Text="Write computer name e.g. COMP7777..." VerticalAlignment="Top" HorizontalAlignment="Left" Margin="13,183,0,0" Foreground="DarkGray" Width="439" Height="19.99" Grid.ColumnSpan="2">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=computerName_textBox1}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style>
						</TextBlock>
						<TextBlock Name="sdRequest_textBlock1" IsHitTestVisible="False" Text="Write ticket number e.g. 222222..." VerticalAlignment="Top" HorizontalAlignment="Left" Margin="13,273,0,0" Foreground="DarkGray" Width="439" Height="19.99" Grid.ColumnSpan="2">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=sdRequest_textBox1}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style>
						</TextBlock>
					</Grid>
				</TabItem>
				<TabItem Name="delRights_tab" Header="Withdraw rights" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="1.428,0,-1.428,0" Background="#FFC2C6C8" Height="22">
					<Grid Width="466" Height="342" Margin="0,10,0,2">
						<Label Name="header_label2" Content="Write ticket data" HorizontalAlignment="Left" Margin="10,2,0,0" VerticalAlignment="Top" Height="30" Width="446" Background="#FFC2C6C8" Foreground="White" HorizontalContentAlignment="Center" VerticalContentAlignment="Center" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="userName_label2" Content="Username" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="computerName_label2" Content="ComputerName" HorizontalAlignment="Left" Margin="10,143,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True"/>
						<Label Name="sdRequest_label2" Content="Ticket number" HorizontalAlignment="Left" Margin="10,233,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True"/>
						<TextBox Name="userName_textBox2" HorizontalAlignment="Left" Height="30" Margin="10,91,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center"/>
						<TextBox Name="computerName_textBox2" HorizontalAlignment="Left" Height="30" Margin="10,178,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center"/>
						<TextBox Name="sdRequest_textBox2" HorizontalAlignment="Left" Height="30" Margin="10,268,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center"/>
						<TextBlock Name="userName_textBlock2" IsHitTestVisible="False" Text="Write user name e.g. alex" VerticalAlignment="Top" HorizontalAlignment="Left" Margin="15,96,0,0" Foreground="DarkGray" Width="439" Height="20">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=userName_textBox2}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style>
						</TextBlock>
						<TextBlock Name="computerName_textBlock2" IsHitTestVisible="False" Text="Write computer name e.g. COMP7777..." VerticalAlignment="Top" HorizontalAlignment="Left" Margin="13,183,0,0" Foreground="DarkGray" Width="439" Height="19.99">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=computerName_textBox2}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style>
						</TextBlock>
						<TextBlock Name="sdRequest_textBlock2" IsHitTestVisible="False" Text="Write ticket number e.g. 222222..." VerticalAlignment="Top" HorizontalAlignment="Left" Margin="13,273,0,0" Foreground="DarkGray" Width="439" Height="19.99">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=sdRequest_textBox2}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style>
						</TextBlock>
						<Button Name="delRights_button" Content="Delete" HorizontalAlignment="Left" Height="32" Margin="342,303,0,0" VerticalAlignment="Top" Width="114" Background="#FFDDDDDD" BorderBrush="{x:Null}"/>
					</Grid>
				</TabItem>
				<TabItem Name="newGroup_tab" Header="Create group" Background="#FFC2C6C8" Margin="2.284,0,-6.284,0" Height="22">
					<Grid Margin="0,10,0,2" Width="466" Height="342">
						<Grid.ColumnDefinitions>
							<ColumnDefinition Width="31*"/>
							<ColumnDefinition Width="202*"/>
						</Grid.ColumnDefinitions>
						<Label Name="header_label3" Content="Write info about computer to create admin group" HorizontalAlignment="Left" Margin="10,2,0,0" VerticalAlignment="Top" Height="30" Width="446" Background="#FFC2C6C8" Foreground="White" HorizontalContentAlignment="Center" VerticalContentAlignment="Center" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="computerName_label3" Content="Computer Name" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True" Grid.ColumnSpan="2"/>
						<TextBox Name="computerName_textBox3" HorizontalAlignment="Left" Height="30" Margin="10,91,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center" Grid.ColumnSpan="2"/>
						<TextBlock Name="computerName_textBlock3" IsHitTestVisible="False" VerticalAlignment="Top" HorizontalAlignment="Left" Margin="15,96,0,0" Foreground="DarkGray" Width="439" Height="20" Grid.ColumnSpan="2">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=computerName_textBox3}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style><Run Text="Введите "/><Run Text="Write computer name e.g. "/><Run Text="COMP7777"/><Run Text="..."/></TextBlock>
						<Button Name="newGroup_button" Content="Create" HorizontalAlignment="Left" Height="32" Margin="280,126,0,0" VerticalAlignment="Top" Width="114" Background="#FFDDDDDD" BorderBrush="{x:Null}" Grid.Column="1"/>
					</Grid>
				</TabItem>
				<TabItem Name="getGroup_tab" Header="Group members" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="7.424,0,-7.426,0" Height="22" Background="#FFC2C6C8">
					<Grid Height="342" Width="466" Margin="0,10,0,2">
						<Label Name="header_label4" Content="Write info about computer to get admin group members" HorizontalAlignment="Left" Margin="10,2,0,0" VerticalAlignment="Top" Height="30" Width="446" Background="#FFC2C6C8" Foreground="White" HorizontalContentAlignment="Center" VerticalContentAlignment="Center" AllowDrop="True" Grid.ColumnSpan="2"/>
						<Label Name="computerName_label4" Content="Computer Name" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" Height="65" Width="446" Background="#FFD65757" Foreground="White" AllowDrop="True"/>
						<TextBox Name="computerName_textBox4" HorizontalAlignment="Left" Height="30" Margin="10,91,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="446" VerticalContentAlignment="Center"/>
						<TextBlock Name="computerName_textBlock4" IsHitTestVisible="False" VerticalAlignment="Top" HorizontalAlignment="Left" Margin="15,96,0,0" Foreground="DarkGray" Width="439" Height="20">
							<TextBlock.Style>
								<Style TargetType="{x:Type TextBlock}">
									<Setter Property="Visibility" Value="Collapsed"/>
									<Style.Triggers>
										<DataTrigger Binding="{Binding Text, ElementName=computerName_textBox4}" Value="">
											<Setter Property="Visibility" Value="Visible"/>
										</DataTrigger>
									</Style.Triggers>
								</Style>
							</TextBlock.Style><Run Text="Введите "/><Run Text="Write computer name e.g. "/><Run Text="COMP7777"/><Run Text="..."/></TextBlock>
						<Button Name="getGroup_button" Content="Get List" HorizontalAlignment="Left" Height="32" Margin="342,126,0,0" VerticalAlignment="Top" Width="114" Background="#FFDDDDDD" BorderBrush="{x:Null}" IsDefault="True"/>
					</Grid>
				</TabItem>
			</TabControl>
			<Label Name="logAndInfo_label0" Content="Action log" HorizontalAlignment="Left" Margin="10,582.714,0,0" VerticalAlignment="Top" Height="25" Width="472" Foreground="#FF9B9999" VerticalContentAlignment="Center" AllowDrop="True"/>
			<RichTextBox Name="logAndInfo_richtextbox0" HorizontalAlignment="Left" Height="178.714" Margin="10,399,0,0" VerticalAlignment="Top" Width="472" ScrollViewer.CanContentScroll="True" VerticalScrollBarVisibility="Auto" Foreground="#FF7A6F6F" IsReadOnly="True">
				<FlowDocument/>
			</RichTextBox>
		</Grid>
</Window>

'@

#Read XAML

try{
    $Form=[Windows.Markup.XamlReader]::Load( (New-Object System.Xml.XmlNodeReader $XAML))
}
catch{
    $returnParams.Code = 999
    $returnParams.Message = "Unable to load Windows.Markup.XamlReader. `
        Some possible causes for this problem include: .NET Framework is missing PowerShell `
        must be launched with PowerShell -sta, invalid XAML code was encountered."
    $returnParams.Level = 'Error'

    Write-Log -Code $returnParams.Code -Level $returnParams.Level -Message $returnParams.Message

    [System.Environment]::Exit(1)
}

#===========================================================================
# Store Form Objects In PowerShell
#===========================================================================
$xaml.SelectNodes("//*[@Name]") | ForEach-Object{Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)}


$LogPath = $env:temp + '\localAdmins'+ $(Get-Date -Format 'ddMMyyyy') + '.log'
$logAndInfo_richtextbox0.AppendText("Journal writes at `"{0}`"`r`n" -f $LogPath)
$logAndInfo_richtextbox0.AppendText("`r`n")
#Textbox wrapper
$Run = New-Object System.Windows.Documents.Run

#Handles add button click event
$addRights_button.Add_Click({
    try{
        $responseTable = New-LocalAdmin -Computer $computerName_textBox1.Text.Trim() `
            -User $userName_textBox1.Text.Trim() `
            -ServiceRequest $sdRequest_textBox1.Text.Trim()
		if($responseTable.code -eq 2001 -or $responseTable.code -eq 2002){
			Set-Clipboard -Value $("Local admin rights are provided to {0} on computer {1}. " `
                -f $userName_textBox1.Text.Trim(), $computerName_textBox1.Text.Trim())
		}
    }
    catch{
        $responseTable.code = 4004;
        $responseTable.message =  'Unknown error. Check the script and log file.'
        $responseTable.loglevel = 'Error'
    }
    finally{
		Write-Log -LoggingPath $LogPath -Message $responseTable.message -Code $responseTable.code -Level $responseTable.loglevel
		$logAndInfo_richtextbox0.AppendText($("{0} [Rights are provided] {1}`n" -f $(Get-Date -Format 'dd-MM-yyyy hh:mm:ss'), $responseTable.message))
		$logAndInfo_richtextbox0.ScrollToEnd()
		$computerName_textBox1.Text = ""
		$userName_textBox1.Text = ""
		$sdRequest_textBox1.Text = ""
    }
})

#Handles del button click event
$delRights_button.Add_Click({
    try{
		$responseTable = Remove-LocalAdmin -Computer $computerName_textBox2.Text.Trim() `
            -User $userName_textBox2.Text.Trim() `
            -ServiceRequest $sdRequest_textBox2.Text.Trim()
		if($responseTable.code -eq 2003){
			Set-Clipboard -Value $("The rights withdrawn from user {0} on computer {1}" `
                -f $userName_textBox2.Text.Trim(), $computerName_textBox2.Text.Trim())
		}
    }
    catch{
        $responseTable.code = 4004;
        $responseTable.message =  'Unknown error. Check the script and log file.'
        $responseTable.loglevel = 'Error'
    }
    finally{
		Write-Log -LoggingPath $LogPath -Message $responseTable.message -Code $responseTable.code -Level $responseTable.loglevel
		$logAndInfo_richtextbox0.AppendText($("{0} [Rights withdrawn] {1}`n" -f $(Get-Date -Format 'dd-MM-yyyy hh:mm:ss'), $responseTable.message))
		$logAndInfo_richtextbox0.ScrollToEnd()
		$computerName_textBox2.Text = ""
		$userName_textBox2.Text = ""
		$sdRequest_textBox2.Text = ""
    }
})

#Handles group add button click event
$newGroup_button.Add_Click({
    try {
        $responseTable = New-AdminGroup -Computer $computerName_textBox3.Text.Trim()
    }
    catch{
        $responseTable.code = 4004;
        $responseTable.message =  'Unknown error. Check the script and log file.'
        $responseTable.loglevel = 'Error'
    }
    finally{
		Write-Log -LoggingPath $LogPath -Message $responseTable.message -Code $responseTable.code -Level $responseTable.loglevel
		$logAndInfo_richtextbox0.AppendText($("{0} [Group created] {1}`n" -f $(Get-Date -Format 'dd-MM-yyyy hh:mm:ss'), $responseTable.message))
		$logAndInfo_richtextbox0.ScrollToEnd()
		$computerName_textBox3.Text = ""
    }
})

#Handles click event of users list get button 
$getGroup_button.Add_Click({
    try {
        $responseTable = Get-AdminGroupMembers -Computer $computerName_textBox4.Text.Trim()
    }
    catch{
        $responseTable.code = 4004;
        $responseTable.message =  'Unknown error. Check the script and log file.'
        $responseTable.loglevel = 'Error'
    }
    finally{
		Write-Log -LoggingPath $LogPath -Message $responseTable.message -Code $responseTable.code -Level $responseTable.loglevel
		$logAndInfo_richtextbox0.AppendText($("{0} [Get members] {1}`n" -f $(Get-Date -Format 'dd-MM-yyyy hh:mm:ss'), $responseTable.message))
		$logAndInfo_richtextbox0.ScrollToEnd()
        $computerName_textBox4.Text = ""
    }
})

# === Show form =====================================================
$Form.ShowDialog() | out-null