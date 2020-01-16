#Best run on a schedule every 24 hours to alert specified users/DL that a user have been added to a sensitive group. This script goes through all named groups, and checks it against a CSV named 
#the same as the AD group. It will send an email every 24 hours, until the user is removed from the AD group, or added to the CSV.

$style = "<style>BODY{font-family: Arial; font-size: 10pt;}"
$style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
$style = $style + "TH{border: 1px solid black; background: #ec732c; padding: 5px; }"
$style = $style + "TD{border: 1px solid black; padding: 5px; }"
$style = $style + "</style>"

$TitleSrv = hostname

#Use encrypted credentials file for O365 connection. Ensure mailbox has sufficient rights to send as mailbox.

$username = "O365Email@company.com"
$encrypted = Get-Content C:\Scripts\ProjUser\encpsu.txt | ConvertTo-SecureString
$credential = New-Object System.Management.Automation.PsCredential($username, $encrypted)

Function Write-Log {

    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information',

        [Parameter()]
        [String]$Global:LogName = "C:\Scripts\Get-ADGrpUpdate\Logs\LogFile_" + (Get-Date -F ddMMyy) + ".csv"
    )
    
    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Message
        Severity = $Severity
    } | Export-Csv -Path $LogName -Append -NoTypeInformation
}

Function Send-ATA`Mail{
    
    $MailSplat = @{
    To = "admin@company.com"
    Subject = ($TitleSrv + " : New users found in sensitive group")
    From = "@servest.co.uk"
    Smtpserver = "smtp.office365.com"
    Port = "587"
    Body = $Body
    }

Send-MailMessage @MailSplat -UseSsl -Credential $Credential -BodyAsHtml -Attachments $LogName
}


function Get-ADGrpUpdate {
    [CmdletBinding()]
    
    Param(
    [Parameter(Position=0,
    Mandatory=$true,
    ValueFromPipeline=$True)]
    [system.string[]]$GroupName

    )

    Begin{
    }

    Process{

        $fnd = 0
        
        $GroupName | % {
                $CurrentGrp = $_

                Try{
                    Set-Location C:\scripts\Get-ADGrpUpdate 
                    $CSV = Import-CSV ($($CurrentGrp) + "_CSV.csv") -ErrorAction "Stop"
                    Write-Log -Message ("CSV Imported Successfully: {0}" -f $CSVFile)
                }
                Catch{
                    Write-Log -Message "Error importing CSV, group exceptions not imported, aborting script" -Severity "Error"
                    Write-Log -Message $_.exception.Message -Severity "Error"
                    #Send-ATAMail -Subject "Get-ADGrpUpdate - ERROR" -Body (Get-Content $LogName)
                    exit
                }

    #Region Get group
                Try{
                    $ADGroup = Get-ADGroup -Identity $CurrentGrp -Server ((Get-ADDomainController -Discover -DomainName "domain.com").Name) -ErrorAction "Stop"
                    Write-Log -Message ("Group variable created with group: {0}" -f $ADGroup)
                }
                Catch {
                    Write-Log -Message ("Unable to Get AD Group {0}, exiting script" -f $GroupName) -Severity "Error"
                    Write-Log -Message $_.exception.Message -Severity "Error"
                    Send-ATAMail -Subject "Clear-ADGroup - ERROR"

                }
        

    #Endregion

            $remUsers = Get-ADGroupMember -Identity $ADGroup -Server "VIC-DC01" | Where {$_.Name -notin (($CSV).GroupExceptions)}
            If($remUsers){
                Write-Log ("Unexpected users found in {0}" -f ($ADGroup).Name)
                $Global:UserStr =  ("Unexpected users found in {0}: <br>`r" -f ($ADGroup).Name)

                $remUsers.Name | %{
                    Write-Log ("New Users: {0}" -f $_)
                    #$UserStr =  ("Unexpected users found in {0} <br>" -f ($ADGroup).Name)
                    $Global:UserStr += "$_ <br>"
                    #$remUsers.Name | % {$UserStr += "$_<br>"}
                    #$Body | Out-File c:\temp\test1.txt -Append
                    $Fnd++
                }
                $Body += "$UserStr<br>"
            }
            Else {
                Write-Log "No Unexpected Users Found"
            }
        }
    }
    
    End{
        If ($fnd -gt 0){
            Try{
                Send-ATAMail -Subject "ADGroup - Users found"
            }
            Catch{
                "Unable to remove Users: "
                Write-Log -Message $_.Exception.Message -Severity "Error"
                Send-ATAMail -Subject "Get-ADGrpUpdate - ERROR"
            }
        }
    }
}

Get-ADGrpUpdate -GroupName "Domain Admins", "Enterprise Admins", "IT_Admins"