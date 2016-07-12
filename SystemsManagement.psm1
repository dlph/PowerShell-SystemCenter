function Select-SMSPackages {
    [cmdletbinding()]
    param()

    process {
        $WQL = @"
select *
from SMS_Package
"@
        return Request-SMSQuery $WQL
    }
}

function Select-SMSAdvertisements {
    [cmdletbinding()]
    param()

    process {
        $WQL = @"
select *
from  SMS_Advertisement
"@

        return Request-SMSQuery -WQL $WQL
    }
}

function Select-SMSSystem {
    [cmdletbinding()]
    param()

    process {
        $WQL = @"
select *
from  SMS_R_System
	inner join SMS_G_System_ADD_REMOVE_PROGRAMS on 
			   SMS_G_System_ADD_REMOVE_PROGRAMS.ResourceID = SMS_R_System.ResourceId
	inner join SMS_G_System_OPERATING_SYSTEM on
			   SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId
"@

        return Request-SMSQuery -WQL $WQL
    }
}

function Select-SMSSystemProgram {
    <#
    .Synopsis
       gets all programs from SCCM with the program and version
    .EXAMPLE
       Select-SMSSystemProgram -ProgramName "acrobat"

    #>
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=0)]
        $ProgramName = 'acrobat'
    )

    Process
    {
        $WQL = @"
SELECT *
FROM  SMS_R_System
INNER JOIN SMS_G_System_ADD_REMOVE_PROGRAMS on SMS_G_System_ADD_REMOVE_PROGRAMS.ResourceID = SMS_R_System.ResourceId
WHERE SMS_G_System_ADD_REMOVE_PROGRAMS.DisplayName like "%$ProgramName%"
AND SMS_R_System.Active = 1
AND SMS_R_System.Client = 1
AND SMS_R_System.Obsolete = 0
"@

        $SMSQuery = Request-SMSQuery -WQL $WQL

        return $SMSQuery
    }
}

function Select-SMSFailedSystemAdvertisement {
    <#
    .Synopsis
       Retrieves Systems from SMS with a failure in the provided Advertisement IDs
    .DESCRIPTION
       Retrieves Systems from SMS with a LastStateName in 'Cancelled', 'Failed', 'Running', or 'Waiting' for the provided Advertisement IDs
    .EXAMPLE
       Select-SMSFailedSystemAdvertisement -AdvertisementIDs @('20', '50')

       Gets all SMS_R_System with a failure
    #>
    [CmdletBinding()]
    Param
    (
        # array of Advertisements to schedule to run
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   ValueFromRemainingArguments=$true,
                   Position=0)]
        [string[]]$AdvertisementIDs,
        # Accepted values - 'Accepted - No Further Status', 'Cancelled', 'Failed', 'No Status', 'Reboot Pending', 'Retrying', 'Running', 'Succeeded', 'Waiting', 'Will Not Rerun'
        [string[]]$LastStateName = @('Cancelled', 'Failed', 'No Status', 'Retrying', 'Running', 'Waiting', 'Accepted - No Further Status')
    )

    Process
    {

# change Advertisement IDs as necessary
# MessageState - https://msdn.microsoft.com/en-us/library/cc146358.aspx
# SMS_R_System WMI class - https://msdn.microsoft.com/en-us/library/cc145392.aspx
$WQL = @"
select *
from SMS_R_System
INNER JOIN SMS_ClientAdvertisementStatus ON SMS_R_System.ResourceID = SMS_ClientAdvertisementStats.ResourceID
where SMS_ClientAdvertisementStatus.AdvertisementID IN ('$($AdvertisementIDs -join "', '")')
AND SMS_ClientAdvertisementStatus.LastStateName IN ('$($LastStateName -join "', '")')
AND SMS_R_System.Active = 1
AND SMS_R_System.Client = 1
AND SMS_R_System.Obsolete = 0
"@

        $SMSQuery = Request-SMSQuery -WQL $WQL

        return $SMSQuery
    }
}

function Select-SMSClientAdvertisements {
    [cmdletbinding()]
    param([Parameter(Mandatory=$false,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)

    process {
        $WQL = @"
select *
from SMS_R_System
	INNER JOIN SMS_ClientAdvertisementStatus ON SMS_R_System.ResourceID = SMS_ClientAdvertisementStatus.ResourceID
    INNER JOIN SMS_Advertisement ON SMS_ClientAdvertisementStatus.AdvertisementID = SMS_Advertisement.AdvertisementID
WHERE SMS_R_System.Name = '$ComputerName'
AND SMS_ClientAdvertisementStatus.LastState != 13
AND SMS_ClientAdvertisementStatus.LastAcceptanceMessageID NOT IN (10018,10019)
"@

        return Request-SMSQuery -WQL $WQL
    }
}

function Select-SMSPendingReboot {
    <#
    .Synopsis
       Retrieves SMS_R_System where a reboot is pending
    .EXAMPLE
       Select-SMSPendingReboot
    #>
    [CmdletBinding()]
    Param()

    Process {
        $WQL = @"
select SMS_R_SYSTEM.ResourceID,
	   SMS_R_SYSTEM.ResourceType,
	   SMS_R_SYSTEM.Name,
	   SMS_R_SYSTEM.SMSUniqueIdentifier,
	   SMS_R_SYSTEM.ResourceDomainORWorkgroup,
	   SMS_R_SYSTEM.Client
from SMS_R_System
	inner join SMS_G_System_PatchStatusEx on SMS_G_System_PatchStatusEx.ResourceID = SMS_R_System.ResourceId
	where SMS_G_System_PatchStatusEx.LastStateName = "reboot pending" 
"@

        Request-SMSQuery -WQL $WQL
    }
}

function Select-SMSNonClientSystems {
    <#
    .Synopsis
       Retuns all Systems without a SCCM Client installed
    .DESCRIPTION
       Same as short
    .EXAMPLE
       Select-NonClientSystems

    .NOTES
        http://www.sccm.blog.com/2012/06/04/collection-queries-wql/
    #>
    [CmdletBinding()]
    Param()

    Process {
        $WQL = @"
SELECT *
FROM SMS_R_System
WHERE SMS_R_System.Client = 0
OR SMS_R_System.Client is null
OR SMS_R_System.Active = 0
OR SMS_R_System.Obsolete = 1
"@

        return Request-SMSQuery -WQL $WQL
    }
}

function Select-SMSUpdates {
    <#
    .Synopsis
       Retrieves all updates 
    .NOTES
    example modified from:
    http://jacobalong.blogspot.com/2009/08/powershell-script-to-report-ms-updates.html
    #>
    [CmdletBinding()]
    Param (
        # Computer
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ComputerName = $env:COMPUTERNAME)

    Process {
        $WQL = @"
select *
from SMS_R_System
	INNER JOIN SMS_UpdateComplianceStatus ON SMS_R_System.ResourceID = SMS_UpdateComplianceStatus.MachineID
	INNER JOIN SMS_SoftwareUpdate ON SMS_UpdateComplianceStatus.CI_ID = SMS_SoftwareUpdate.CI_ID
WHERE SMS_R_System.Name = '$ComputerName'
"@
        
        return Request-SMSQuery -WQL $WQL
    }
}

function Request-SMSQuery {
    [cmdletbinding()]
    param([Parameter(Mandatory=$false,
                     ValueFromPipeline=$true)]
          [string]$SMServer = $MyInvocation.MyCommand.Module.PrivateData['SMServer'],
          [Parameter(Mandatory=$false,
                     ValueFromPipeline=$true)]
          [string]$SiteCode,
          [Parameter(Mandatory=$True,
                     ValueFromPipeline=$false)]
          [string]$WQL)

    begin {
        <#
        $SQLServer = "" #use Server\Instance for named SQL instances! 
        $SQLDBName = ""
        
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Server = $SQLServer; Database = $SQLDBName; Trusted_Connection = True; Integrated Security = True"
        #>
    }

    process {
        # $SqlQuery = "select * from authors WHERE Name = 'John Simon'"

        <#
        $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
        $SqlCmd.CommandText = $WQL
        $SqlCmd.Connection = $SqlConnection

        
        $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
        $SqlAdapter.SelectCommand = $SqlCmd

        $DataSet = New-Object System.Data.DataSet
        $SqlAdapter.Fill($DataSet)

        $DataSet.Tables[0]
        #>

        $SMSQuery = Get-WmiObject -ComputerName $SMServer -Namespace "root\sms\site_$SiteCode" -Query $WQL

        return $SMSQuery
    }

    end {

        <#
        $SqlConnection.Close()
        #>
        
    }
}

function Get-SMSScheduleMethods {
    <#
    .Synopsis
       Returns a WMI class that provides methods to decode service window schedules
    .EXAMPLE
       # gets the service window from the computer
       $CCMServiceWindow = get-wmiobject -namespace "root\CCM\Policy\Machine\ActualConfig" -Class CCM_ServiceWindow

       # returns the WMI class
       $SMSScheduleMethods = Get-SMSScheduleMethods

       # decodes the schedule
       $ReadFromStringResult = $SMS_ScheduleMethods.ReadFromString( $CCMServiceWindow.Schedules )

       # prints off the schedule information
       $ReadFromStringResult.TokenData
    .LINKS
    Microsoft WMI class 
    https://msdn.microsoft.com/en-us/library/cc143477.aspx
    #>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false,
                     ValueFromPipeline=$false)]
          [string]$SMServer,
          [Parameter(Mandatory=$false,
                     ValueFromPipeline=$false)]
          [string]$SiteCode)

    Process
    {
        return gwmi -ComputerName $SMServer -Namespace "root\SMS\Site_$SiteCode" -Class SMS_ScheduleMethods -List
    }
}

function ConvertFrom-ConfigurationManagerDateTime {
    <#
    .Synopsis
       Converts a weird 20140828000000.000000+*** datetime to readable datetime
    .DESCRIPTION
       Converts a weird 20140828000000.000000+*** datetime to readable datetime
    .EXAMPLE
       ConvertFrom-ConfigurationManagerDateTime -DateTime 20140828000000.000000+***
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$DateTime
    )
    
    process {
        return [System.Management.ManagementDateTimeconverter]::ToDateTime($DateTime)
    }
}