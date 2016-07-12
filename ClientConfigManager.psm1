function Invoke-CCMRepair {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)

    process {
        $CCMRepairResult = $false
        $Proc = Get-Process -Name ccmrepair* -ComputerName $ComputerName 
        if ($Proc) {
            Write-Verbose "[$ComputerName] SCCM Repair is already running."

            $CCMRepairResult = $false
        } else { 
            $SMSCli = [wmiclass]"\\$ComputerName\root\ccm:sms_client" 
            Write-Verbose "[$ComputerName] Trigger the SCCM Repair."
            # The actual repair is put in a variable, to trap unwanted output. 
            $repair = $SMSCli.RepairClient()

            $CCMRepairResult = $True
        }

        return $CCMRepairResult
    }
}

function Invoke-CCMAction {
    <#
    .Synopsis
       Initiates a CCM Action for a computer
    .EXAMPLE
       Invoke-CCMAction -ComputerName ComputerA -Action HWInventory

       Initiates the Hardware inventory Action for ComputerA
    .EXAMPLE
       "ComputerA", "ComputerB" | Invoke-CCMAction -ComputerName ComputerA -Action CertificateMaintenance

       Initiates the Certificate Maintenance task for ComputerA and ComputerB via the Pipeline
    .NOTES
        http://serverfault.com/questions/364555/what-do-each-of-the-actions-in-the-sccm-client-actually-do
    #>
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName,
          [Parameter(Mandatory=$True,
                     ValueFromPipeline=$false)]
          [ValidateSet('HWInventory', 'HWInventoryFull', 'SWInventory', 'SWInventoryFull', 'DataDiscovery', 'DataDiscoveryFull', 'FileCollect', 'FileCollectFull', 'SWUpdateDeploy', 'SWUpdateScan', 'MachinePolicy', 'MachinePolicyHardReset', 'CertificateMaintenance', 'CacheCleanupMessage')]
          [string]$Action)

    process {
        $ActionInvoked = $false
        try {
            switch ($Action) {
                "HWInventory" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000001}"
                    $ActionName = "Hardware Inventory Cycle (Delta)"
                }
                "HWInventoryFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000001}"
                    $ActionName = "Hardware Inventory Cycle (Full)"
                }
                "SWInventory" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000002}"
                    $ActionName = "Software Inventory Cycle (Delta)"
                }
                "SWInventoryFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000002}"
                    $ActionName = "Software Inventory Cycle (Full)"
                }
                "DataDiscovery" {
                    # Send a Heartbeat back to the server
                    $ScheduleID = "{00000000-0000-0000-0000-000000000003}"
                    $ActionName = "Discovery Data Collection Cycle (Delta)"
                }
                "DataDiscoveryFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000003}"
                    $ActionName = "Discovery Data Collection Cycle (Full)"
                }
                "FileCollect" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000010}"
                    $ActionName = "File Collection Cycle (Delta)"
                }
                "FileCollectFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000010}"
                    $ActionName = "File Collection Cycle (Full)"
                } 
                "SWUpdateDeploy" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000108}"
                    $ActionName = "Software Updates Deployment Evaluation Cycle"
                }
                "SWUpdateScan" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000113}"
                    $ActionName = "Software Updates Scan Cycle"
                }
                "MachinePolicy" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000021}"
                    $ActionName = "Machine Policy Cycle"
                }
                "MachinePolicyHardReset" {
                    gwmi -ComputerName $ComputerName -Namespace root\ccm\Policy -Class CCM_SoftwareDistribution -ErrorAction Stop | %{ $_.Delete() }
                    gwmi -ComputerName $ComputerName -Namespace root\ccm\Policy -Class CCM_Scheduler_ScheduledMessage -ErrorAction Stop | %{ $_.Delete() }
                    
                    gwmi -ComputerName $ComputerName -Namespace root\ccm\Scheduler -Class CCM_Scheduler_History -ErrorAction Stop | %{ $_.Delete() }

                    gwmi -ComputerName $ComputerName -Namespace root\ccm\Scanagent -Class CCM_ScanToolHistory -ErrorAction Stop | %{ $_.Delete() }

                    $ScheduleID = "{00000000-0000-0000-0000-000000000021}"
                    $ActionName = "Machine Policy Cycle"
                }
                "CertificateMaintenance" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000051}"
                    $ActionName = "Certificate Maintenance Cycle"
                }
                "CacheCleanupMessage" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000112}"
                    $ActionName = "Cache Cleanup Message"
                }
                default {
                    Write-Host "[$ComputerName] Unidentified action: $Action"
                    return $false
                }
            }

            if($action -imatch "full"){
                #Clearing HW or SW inventory delta flag...
                $wmiQuery = "\\$ComputerName\root\ccm\invagt:InventoryActionStatus.InventoryActionID=$ScheduleID"
                $checkdelete = ([wmi]$wmiQuery).Delete()
            }

            #Invoking $action ...
            Write-Verbose "[$ComputerName] Invoking action $ActionName"
            $SMSCli = [wmiclass]"\\$ComputerName\root\ccm:SMS_Client"
            $TriggerSchedule = $SMSCli.TriggerSchedule($ScheduleID)

            $ActionInvoked = $true
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return $ActionInvoked
    }
}

function Get-CCMLastCycleStartedAction {
[cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName,
          [Parameter(Mandatory=$True,
                     ValueFromPipeline=$false)]
          [ValidateSet('HWInventory', 'HWInventoryFull', 'SWInventory', 'SWInventoryFull', 'DataDiscovery', 'DataDiscoveryFull', 'FileCollect', 'FileCollectFull', 'SWUpdateDeploy', 'SWUpdateScan', 'MachinePolicy', 'MachinePolicyHardReset', 'CertificateMaintenance')]
          [string]$Action)

    process {
        $LastCycleStartedDate = [datetime]::MinValue

        try {
            switch ($Action) {
                "HWInventory" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000001}"
                    $ActionName = "Hardware Inventory Cycle (Delta)"
                }
                "HWInventoryFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000001}"
                    $ActionName = "Hardware Inventory Cycle (Full)"
                }
                "SWInventory" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000002}"
                    $ActionName = "Software Inventory Cycle (Delta)"
                }
                "SWInventoryFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000002}"
                    $ActionName = "Software Inventory Cycle (Full)"
                }
                "DataDiscovery" {
                    # Send a Heartbeat back to the server
                    $ScheduleID = "{00000000-0000-0000-0000-000000000003}"
                    $ActionName = "Discovery Data Collection Cycle (Delta)"
                }
                "DataDiscoveryFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000003}"
                    $ActionName = "Discovery Data Collection Cycle (Full)"
                }
                "FileCollect" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000010}"
                    $ActionName = "File Collection Cycle (Delta)"
                }
                "FileCollectFull" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000010}"
                    $ActionName = "File Collection Cycle (Full)"
                } 
                "SWUpdateDeploy" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000108}"
                    $ActionName = "Software Updates Deployment Evaluation Cycle"
                }
                "SWUpdateScan" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000113}"
                    $ActionName = "Software Updates Scan Cycle"
                }
                "MachinePolicy" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000021}"
                    $ActionName = "Machine Policy Cycle"
                }
                "MachinePolicyHardReset" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000021}"
                    $ActionName = "Machine Policy Cycle"
                }
                "CertificateMaintenance" {
                    $ScheduleID = "{00000000-0000-0000-0000-000000000051}"
                    $ActionName = "Certificate Maintenance Cycle"
                }
                default {
                    throw "Unidentified action: $Action"
                }
            }

            $InventoryActionStatus = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\invagt -Class InventoryActionStatus -ErrorAction Stop

            $InventoryAction = $InventoryActionStatus | ?{ $_.InventoryActionID -eq $ScheduleID }

            if (!$InventoryAction) {
                throw "Unable to find last cycle started for $($ActionName): $ScheduleId"
            }

            $LastCycleStartedDate = [management.managementDateTimeConverter]::ToDateTime($InventoryAction.LastCycleStartedDate)
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return $LastCycleStartedDate
    }
}

function Invoke-SMSAction {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName,
          [Parameter(Mandatory=$True,
                     ValueFromPipeline=$false)]
          [ValidateSet('DCMScan')]
          [string]$Action)

    process {
        switch ($Action) {
            "DCMScan" {
                $SMSDesireedConfiguration = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration -List
                $Results = $SMSDesireedConfiguration.GetInstances() | %{ $SMSDesireedConfiguration.TriggerEvaluation($_.Name, $_.Version) }

                if (($Results | ?{ $_.ReturnValue -ne 0 } | measure).Count -gt 0) {
                    Write-Warning "[$ComputerName] SMSAction - Unable to trigger evaluation for all Desired Configurations"
                    return $false
                }
                return $True
            }
        }


        # nothing was ran??
        return $false
    }
}

function Reset-CCMPolicy {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    process {
        $SMSClient = Get-WmiObject -ComputerName $ComputerName -Class sms_client -Namespace root\ccm -List
        $SMSClient.ResetPolicy()
    }
}

function Invoke-CCMAdvertisement {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName,
          [Parameter(Mandatory=$false,
                     ValueFromPipeline=$false)]
          [ValidateNotNullOrEmpty()]
          [string]$AdvertisementID,
          [Parameter(Mandatory=$false,
                     ValueFromPipeline=$false)]
          [ValidateNotNullOrEmpty()]
          [string]$PackageID)

    process {
        $AdvertisementInvoked = $false

        try {
            $SMSClient = [WmiClass]"\\$ComputerName\ROOT\ccm:SMS_Client"
            $CCMSoftwareDistributions = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\Policy\Machine\ActualConfig -Class CCM_SoftwareDistribution -ErrorAction Stop
            $ScheduledMessages = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\Policy\Machine\ActualConfig -Class CCM_Scheduler_ScheduledMessage -ErrorAction Stop

            $SoftwareDisributions = $CCMSoftwareDistributions | ?{ ($_.ADV_AdvertisementID -eq $AdvertisementID) -or ($_.PKG_PackageID -eq $PackageID) }
        
            foreach ($SoftwareDistribution in $SoftwareDisributions) {
                $ReRunAdverts = $ScheduledMessages | ?{ $_.ScheduledMessageID -like ("{0}-{1}-*" -f $SoftwareDistribution.ADV_AdvertisementID, $($SoftwareDistribution.PKG_PackageID)) }

                if (($ReRunAdverts | measure).Count -eq 0) {
                    Write-Verbose "[$ComputerName] No ScheduledMessage(s) found for Advertisement $($SoftwareDistribution.ADV_AdvertisementID) and Package $($SoftwareDistribution.PKG_PackageID)"
                } elseif (($ReRunAdverts | measure | select -ExpandProperty Count) -eq 1) {
                    Write-Verbose "[$ComputerName] settings MandatoryAssignment and RepeatRunBehavior"
                    $SoftwareDistribution.ADV_MandatoryAssignments = "True"
                    $SoftwareDistribution.ADV_RepeatRunBehavior = "RerunAlways"
                    $SoftwareDistribution.Put() | Out-Null

                    Write-Verbose "[$ComputerName] ReRunning Scheduled Message: $($ReRunAdverts.ScheduledMessageID)"
                    $ReRunAdverts.ScheduledMessageID | %{ $SMSClient.TriggerSchedule($_) } | Out-Null

                    # TODO check to see if it was successfully scheduled before returning true
                    # $ExecutionRequests = gwmi -ComputerName $ComputerName -Class CCM_ExecutionRequestEx -Namespace root\ccm\softmgmtagent
                
                    $AdvertisementInvoked = $True
                } else {
                    Write-Warning "[$ComputerName] Multiple Schedules found"
                }
            }
            # TODO: override service window?
            # $ReadFromStringResult = Get-WmiObject -Computer $ComputerName -Namespace "root\CCM\Policy\Machine\ActualConfig" -Class CCM_ServiceWindow
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return $AdvertisementInvoked
    }
}

function Remove-CCMRunningJobs {
    <#
    .Synopsis
       Remove failed Running TaskSequences and Running Jobs
    .DESCRIPTION
        Task Sequence:
            Kills the Task Sequence Manager (TSManager) process, deletes temporary Task Sequence folders, and resets Paused Software Distribution Registry State keys.

            Deletes any jobs that that are in a state of Completed with a CompletionState of Failure
        Jobs:
            Removes any jobs in a State of WaitingContent and CompletionState of Failure
    .EXAMPLE
       Remove-CCMRunningJobs -ComputerName $env:ComputerName
    #>
    [CmdletBinding()]
    Param (# The name of the computer to query
           [Parameter(Mandatory=$true,
                      ValueFromPipeline = $true,
                      ValueFromPipelineByPropertyName=$true,
                      Position=0)]
           [string]$ComputerName,
           [ValidateSet('All', 'Running', 'Ready', 'WaitingContent', 'Failure')]
           [string]$JobState = "WaitingContent")

    Process {
        $Result = $false

        # check for WaitingContent_failed ExecutionRequests
        try {
            $ExecutionRequest = gwmi -ComputerName $ComputerName -Namespace root\ccm\SoftMgmtAgent -Class CCM_ExecutionRequest -ErrorAction SilentlyContinue
            $ExecutionRequestEx = gwmi -ComputerName $ComputerName -Namespace root\ccm\SoftMgmtAgent -Class CCM_ExecutionRequestEx -ErrorAction Stop
            $TSExecutionRequest = gwmi -ComputerName $ComputerName -Namespace root\ccm\SoftMgmtAgent -Class CCM_TSExecutionRequest -ErrorAction Stop

            switch($JobState) {
                "All" {
                    $TSManagerProcess = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "Name='TSManager.exe'"

                    if ($TSManagerProcess -ne $null) {
                        $TSManagerProcess.Terminate() | Out-Null

                        # clean paused Registry Keys
                        $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$ComputerName).OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\SMS\Mobile Client\Software Distribution\State").GetValue("Paused")
                        If ($RegistryKey -eq 1) {
                            [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$ComputerName).OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\SMS\Mobile Client\Software Distribution\State").SetValue("Paused", 0)
                            [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$ComputerName).OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\SMS\Mobile Client\Software Distribution\State").SetValue("PausedCookie", 0)
                        }
                    }

                    # remove temporary folders
                    if (Test-Path "\\$ComputerName\c`$\_SMSTaskSequence") {
                        Remove-Item "\\$ComputerName\c`$\_SMSTaskSequence" -Recurse -Force
                    }

                    if (Test-Path "\\$ComputerName\c`$\SMSTSLog") {
                        Remove-Item "\\$ComputerName\c`$\SMSTSLog" -Recurse -Force
                    }

                    $ExecutionRequestEx | %{
                        Write-Warning "[$ComputerName] Removed WaitingContent Advertisement: $($_.AdvertID), $($_.MIFPackageName)"
                        $_.Delete()
                        $Result = $true
                    }

                    # remove the task sequence requests
                    $TSExecutionRequest | %{
                        Write-Warning "[$ComputerName] Removed TS-Advertisement: $($_.AdvertID), $($_.MIFPackageName)"
                        $_.Delete()
                        $Result = $true
                    }
                }
                default {
                    $ExecutionRequestEx | ?{ $_.State -eq $JobState } | %{
                        Write-Warning "[$ComputerName] Removed WaitingContent Advertisement: $($_.AdvertID), $($_.MIFPackageName)"
                        $_.Delete()
                        $Result = $true
                    }

                    $TSExecutionRequest | ?{ $_.State -eq $JobState } | %{
                        Write-Warning "[$ComputerName] Removed TS-Advertisement: $($_.AdvertID), $($_.MIFPackageName)"
                        $_.Delete()
                        $Result = $true
                    }
                }
            }

        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return $Result
    }
}

function Get-CCMSoftwareUpdateStatus {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param (
        # The name of the computer to query
        [Parameter(Mandatory=$true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ComputerName,
        [ValidateSet('All')]
        [string]$Status = "All"
    )

    process {
        $Results = @()
        try {
            $UpdateCIAssignments = gwmi -ComputerName $ComputerName -Namespace root\ccm\Policy\Machine\RequestedConfig -Class CCM_UpdateCIAssignment -ErrorAction Stop

            if ($UpdateCIAssignments.Count -eq 0) {
                throw "no UpdateCIAssignments found"
            }

            $UpdateStatus = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\SoftwareUpdates\UpdatesStore -Class CCM_UpdateStatus -ErrorAction Stop

            if ($UpdateStatus.Count -eq 0) {
                throw "no UpdateStatus found"
            }

            $UpdateIds = New-Object System.Collections.Generic.HashSet[string]
            foreach ($UpdateCIAssignment in $UpdateCIAssignments) {
                $UpdateCIAssignment.AssignedCIs | %{ [xml]$_ } | %{
                    $UpdateId = $_.SelectNodes("/CI/ApplicabilityCondition/ApplicabilityRule/UpdateId") | select -ExpandProperty '#text'
                    # Convert enforcement deadline to friendly
                    # [System.Management.ManagementDateTimeConverter]::ToDateTime($_.EnforcementDeadline)
                    [void]$UpdateIds.Add($UpdateId)
                }
            }

            # just for fun - tell them if they are missing updates
            if (($UpdateStatus | ?{ $_.Status -eq "Missing" } | ?{ $UpdateIds.Contains($_.UniqueId) } | measure | select -ExpandProperty Count) -gt 0) {
                Write-Warning "[$ComputerName] approved updates from server need to be installed"
            }


            switch ($Status) {
                "All" {
                    $Results = $UpdateStatus | ?{ $UpdateIds.Contains($_.UniqueId) }
                }
                
                default {
                    $Results = $UpdateStatus | ?{ $_.Status -eq $Status } | ?{ $UpdateIds.Contains($_.UniqueId) }
                }
            }

        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }


        return $Results
    }
}

function Get-CCMSiteCode {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    process {
        $SiteCode = ""
        try {
            $SMSClient = [WmiClass]"\\$ComputerName\ROOT\ccm:SMS_Client"

            $SiteCode = $SMSClient.GetAssignedSite().sSiteCode
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }
        return $SiteCode
    }
}

function Set-CCMSiteCode {
    <#
    .Synopsis
       Sets the CCM Client SiteCode
    .EXAMPLE
       Set-CCMSiteCode -ComputerName "Comp1" -SiteCode "SiteA"
    #>
    [CmdletBinding()]
    Param
    (
        # HostName of the computer to set the sitecode of
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$ComputerName,
        # SiteCode to set on the computer
        [string]$SiteCode
    )

    Process {
        try {
            $SMSClient = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm -Class SMS_Client -List
            $SMSClient.SetAssignedSite($SiteCode)
            $SMSClient.Put()
            return $true
        } catch {
            Write-Warning "[$ComputerName] unable to set sitecode"
        }

        return $false
    }
}


function Clear-CCMCache {
    <#
    .Synopsis
       Deletes the CCM Cache

    .DESCRIPTION
        Deletes all CacheInfo and CacheInfoEx instances along with the directory they are associated with
    .EXAMPLE
       Clear-CCMCache -Computer ComputerA

       Clears the cache 
    #>
    [CmdletBinding()]
    Param
    (
        # HostName/IP of computer that is in need of a cache cleanup
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Computer)

    Process
    {
        try {
            $CacheInfoInstances = gwmi -ComputerName $Computer -Namespace root\ccm\SoftMgmtAgent -Class CacheInfo -ErrorAction SilentlyContinue
            $CacheInfoExInstances = gwmi -ComputerName $Computer -Namespace root\ccm\SoftMgmtAgent -Class CacheInfoEx -ErrorAction Stop

            if ($CacheInfoExInstances -ne $null) {
                foreach ($CacheInfo in $CacheInfoExInstances) {
                    $CacheLocation = "\\{0}\{1}" -f $Computer, ($CacheInfo.Location -replace "c:","c`$")
                    if (Test-Path $CacheLocation) {
                        Remove-Item $CacheLocation -Recurse -Force
                    }

                    $CacheInfo.Delete()
                }
            }

            if ($CacheInfoInstances -ne $null) {
                foreach ($CacheInfo in $CacheInfoInstances) {
                    $CacheLocation = "\\{0}\{1}" -f $Computer, ($CacheInfo.Location -replace "c:","c`$")
                    if (Test-Path $CacheLocation) {
                        Remove-Item $CacheLocation -Recurse -Force
                    }

                    $CacheInfo.Delete()
                }
            }

            $CacheConfig = gwmi -ComputerName $Computer -Namespace root\ccm\SoftMgmtAgent -Class CacheConfig

            $CacheConfigLocation = ("\\{0}\{1}" -f $Computer, $CacheConfig.Location -replace "c:", "c`$")
            $OrphanedItems = gci -Path $CacheConfigLocation
            if (($OrphanedItems | measure | select -ExpandProperty Count) -gt 0) {
                Write-Verbose ("[{0}] removing {1} orphaned items" -f $Computer, ($OrphanedItems | measure | select -ExpandProperty Count))

                $OrphanedItems | %{ Remove-Item $_.FullName -Recurse -Force }
            }
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }
    }
}

#region Services/Processes

function Start-CCMServices {
    <#
    .Synopsis
       Start the Services related to CCM
    .DESCRIPTION
       Starts the CCMExec and SMSTSMgr Services
    .EXAMPLE
       Start-CCMServices -Computer Computer1
    #>

    [CmdletBinding()]
    Param (# Name/IP of the computer to stop services on
           [Parameter(Mandatory=$true,
                      ValueFromPipeline=$true,
                      Position=0)]
           [string]$Computer)

    Process
    {
        $WMIFilters = @("Name='CCMExec'", "Name='smstsmgr'")

        try {
            for($i = 0; $i -lt $WMIFilters.Count; $i++) {

                $WMIService = Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter $WMIFilters[$i] -ErrorAction Stop

                if ($WMIService -eq $null) {
                    throw "$($WMIService.Name) service not found"
                }

                if (-not (Set-CCMServiceState -WmiService $WMIService -NewState Running -TimeOutSpan ([System.TimeSpan]::FromSeconds(30)))) {
                    throw "unable to start $($WMIService.DisplayName)"
                }
            }
        } catch {
            return $false
        }

        return $true
    }
}

function Stop-CCMServices {
    <#
    .Synopsis
       Stops the Services related to CCM
    .DESCRIPTION
       Stops the CCMExec and SMSTSMgr Services
    .EXAMPLE
       Stop-CCMServices -Computer Computer1
    #>

    [CmdletBinding()]
    Param (# Name/IP of the computer to stop services on
           [Parameter(Mandatory=$true,
                      ValueFromPipeline=$true,
                      Position=0)]
           [string]$Computer)

    Process
    {
                $WMIFilters = @("Name='CCMExec'", "Name='smstsmgr'")

        try {
            for($i = 0; $i -lt $WMIFilters.Count; $i++) {

                $WMIService = Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter $WMIFilters[$i] -ErrorAction Stop

                if ($WMIService -eq $null) {
                    throw "$($WMIService.Name) service not found"
                }

                if (-not (Set-CCMServiceState -WmiService $WMIService -NewState Stopped -TimeOutSpan ([System.TimeSpan]::FromSeconds(30)))) {
                    throw "unable to start $($WMIService.DisplayName)"
                }
            }
        } catch {
            return $false
        }

        return $true
    }
}

function Set-CCMServiceState {
    <#
    .Synopsis
       Changes a service to a new service state
    .EXAMPLE
       Set-CCMServiceState -Computer ComputerA -WMIFilter "Name='CCMExec'" -NewState Running -TimeOutSpan ([System.TimeSpan]::FromSeconds(70))

       Change the CCMExec service to State of Running and wait only 70 seconds before determining it unsuccessful
    .EXAMPLE
       Set-CCMServiceState -Computer "192.168.1.101" -WMIFilter "Name='smstsmgr'" -NewState Stopped -TimeOutSpan ([System.TimeSpan]::FromMinutes(5))

       Wait 5 minutes while attempting to stop the SMSTSMgr service
    #>
    [CmdletBinding()]
    Param
    (
        # Win32_Service that needs the state changed
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $WmiService,

        [ValidateSet('Running', 'Stopped', 'Paused')]
        [string]$NewState = "Stopped",

        # TimeSpan to wait before giving up
        [System.TimeSpan]$TimeOutSpan = [System.TimeSpan]::FromSeconds(15)
    )

    Process
    {
        $IsNewState = $false

        $StopWatch = New-Object System.Diagnostics.Stopwatch

        # start the stopwatch to see how long it takes to stop the service
        $StopWatch.Start()

        try {
            if ($WmiService.State -eq $NewState) {
                # the service successfully stopped
                $IsNewState = $true
            } else {
                $WmiAction = $null

                switch ($NewState) {
                    "Running" {
                        switch ($WmiService.State) {
                            "Start Pending" {
                                Start-Sleep -Seconds 1
                            }
                            "Resume Pending" {
                                $StateVerb = "Resuming"
                                $WmiAction = $WmiService.ResumeService()
                            }
                            default {
                                $StateVerb = "Starting"
                                $WmiAction = $WmiService.StartService()
                            }
                        }
                    }

                    "Stopped" {
                        switch ($WmiService.State) {
                            "Stop Pending" {
                                Start-Sleep -Seconds 1
                            }
                            default {
                                $StateVerb = "Stopping"
                                $WmiAction = $WmiService.StopService()
                            }
                        }
                    }

                    "Paused" {
                        switch ($WmiService.State) {
                            "Pause Pending" {
                                Start-Sleep -Seconds 1
                            }
                            default {
                                $StateVerb = "Pausing"
                                $WmiAction = $WmiService.PauseService()
                            }
                        }
                    }

                    default {
                        throw "Unknown NewState $NewState"
                    }
                }

                if ($WmiAction -eq $null) {
                    Write-Verbose "[$($WmiService.SystemName)] No action taken for $($WmiService.DisplayName) service"
                } elseif ($WmiAction.ReturnValue -eq 0) {
                    Write-Verbose "[$($WmiService.SystemName)] $StateVerb $($WmiService.DisplayName) service"
                } else {
                    # more information on return values can be found in Microsofts Documentation (https://msdn.microsoft.com/en-us/library/aa393660%28v=vs.85%29.aspx)
                    throw "$StateVerb $($WmiService.DisplayName) service failed with ReturnValue $($WmiAction.ReturnValue)"
                }

                # re-query wmi to get new state
                $WmiService = [wmi]$WmiService.Path

                # wait at least 1 second before trying again
                if ($StopWatch.Elapsed.Seconds -eq 0) {
                    Start-Sleep -Seconds 1
                }
            }
        } catch {
            Write-Warning "[$($WmiService.SystemName)] $($_.Exception.Message)"
            return $false
        }
        
        # stop counting
        $StopWatch.Stop()

        if ($IsNewState -eq $true) {
            return $true
        }

        if ([System.TimeSpan]::Compare($TimeOutSpan, $StopWatch.Elapsed) -ne 1) {
            Write-Verbose "[$($WmiService.SystemName)] Service did not change state in the given amount of time"
            return $false
        }

        Set-CCMServiceState -WMIService $WmiService -NewState $NewState -TimeOutSpan $TimeOutSpan.Subtract($StopWatch.Elapsed)
    }
}

#endregion

#region Certificate Maintenance

function Get-SMSCertificates {
    param([Parameter(Position=0,Mandatory=$false)]
          [string]$Computer)
    
    process {
        try {
            $CertificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Computer\SMS", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $CertificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            return $CertificateStore.Certificates | ?{ ($_.FriendlyName -like "SMS Encryption Certificate") -or ($_.FriendlyName -like "SMS Signing Certificate") }
        } catch {
            Write-Warning "[$Computer] $($_.Exception.Message)"
        }

        return $null
    }
}

function Remove-SMSCertificates {
    <#
    .Synopsis
        Removes the SMS Certificates so they regenerate
    .EXAMPLE
       Remove-SMSCertificates -Computer Computer1
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param(# Computer Name/IP that the Certificates should be removed from
          [Parameter(Mandatory=$true,
                     ValueFromPipeline=$true,
                     Position=0)]
          [string]$Computer)

    Process
    {
        try {
            # stop CCM Services
            $WMIFilters = @("Name='CCMExec'", "Name='smstsmgr'", "Name='cryptsvc'")

            for($i = 0; $i -lt $WMIFilters.Count; $i++) {

                $WMIService = Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter $WMIFilters[$i] -ErrorAction Stop
                                
                if ($WMIService -eq $null) {
                    throw "$($WMIService.Name) service not found"
                }

                $StopServiceResult = Set-CCMServiceState -WmiService $WMIService -NewState Stopped -TimeOutSpan ([System.TimeSpan]::FromSeconds(15)) -ErrorAction Stop

                if (-not $StopServiceResult) {
                    throw "Unable to Stop Service $($WMIService.DisplayName)"
                }
            }
            
            # Open Certificate Store and remove the invalid certificates
            $CertificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Computer\sms", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $CertificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        
            foreach ($SMSCertificate in ($CertificateStore.Certificates | ?{ ($_.FriendlyName -like "SMS Encryption Certificate") -or ($_.FriendlyName -like "SMS Signing Certificate") }) ) {
                $CertificateStore.Remove($SMSCertificate)
            }

            $CertificateStore.Close()


            # restart CCM Services
            for($i = 0; $i -lt $WMIFilters.Count; $i++) {

                $WMIService = Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter $WMIFilters[$i] -ErrorAction Stop
                                
                $StopServiceResult = Set-CCMServiceState -WmiService $WMIService -NewState Running -TimeOutSpan ([System.TimeSpan]::FromSeconds(15)) -ErrorAction Stop

                if (-not $StopServiceResult) {
                    throw "Unable to Start Service $($WMIService.DisplayName)"
                }
            }
        } catch {
            Write-Warning "[$Computer] $($_.Exception.Message)"
            return $false
        }
        
        return $true
    }
}

#endregion


function Get-CCMGUID {
    [cmdletbinding()]
    [OutputType([int])]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    process {
        $ClientId = -1
        try {
            $CCMClient = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm -Class CCM_Client -ErrorAction Stop

            $ClientId = $CCMClient.ClientId
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return -1
    }
}

function Get-CCMManagementPoint {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    process {
        try {
            $SMSAuthority = gwmi -ComputerName $ComputerName -Class SMS_Authority -Namespace root\ccm -ErrorAction Stop

            return $SMSAuthority.CurrentManagementPoint
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return ""
    }
}

function Get-CCMClientVersion {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)

    process {
        try {
            $SMSClient = Get-WmiObject -ComputerName $ComputerName -Class sms_client -Namespace root\ccm -ErrorAction Stop

            return $SMSClient.ClientVersion
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }
    }
}

function Get-CCMLastHWInventory {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    
    process {
        $LastHWInventoryDate = [datetime]::MinValue

        try {
            $InventoryActionStatus = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\invagt -Class InventoryActionStatus

            $HWInventoryActionStatus = $InventoryActionStatus | ?{ $_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000001}" }

            if (!$HWInventoryActionStatus) {
                throw "Unable to find SoftwareInventoryActionStatus"
            }

            $LastHWInventoryDate = [management.managementDateTimeConverter]::ToDateTime($HWInventoryActionStatus.LastCycleStartedDate)
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return $LastHWInventoryDate
    }
}

function Get-CCMLastSWInventory {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    process {
        $LastSWInventoryDate = [datetime]::MinValue

        try {
            $InventoryActionStatus = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\invagt -Class InventoryActionStatus

            $SWInventoryActionStatus = $InventoryActionStatus | ?{ $_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000002}" }

            if (!$SWInventoryActionStatus) {
                throw "Unable to find SoftwareInventoryActionStatus"
            }

            $LastSWInventoryDate = [management.managementDateTimeConverter]::ToDateTime($SWInventoryActionStatus.LastCycleStartedDate)
        } catch {
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        return $LastSWInventoryDate
    }
}

function Get-CCMAdvertisements {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)

    process {
        $Advertisements = gwmi -Namespace ROOT\CCM\Policy\Machine\ActualConfig -ComputerName $ComputerName -Class CCM_SoftwareDistribution

        # $InstalledSoftware = gwmi -ComputerName $ComputerName -Namespace ROOT\cimv2\sms -Class SMS_InstalledSoftware
        
        # TODO - something for actually determining if adv is installed
        #$ProgramRequirements = [xml]$Advertisements[0].PRG_Requirements

        #$InstalledSoftware | ?{ $_.ProductCode -eq $ProgramRequirements.SWDReserved.ProductCode }

        return $Advertisements
    }
}


function Get-CCMServiceWindows {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    param(# name of the computer you wish to interrogate
          [Parameter(Mandatory=$true,
                     ValueFromPipelineByPropertyName=$true,
                     Position=0)]
          $ComputerName)

    begin {
        $SMSScheduleMethods = Get-SMSScheduleMethods
    }

    process {
        $CCMServiceWindow = Get-WmiObject -Computer $ComputerName -Namespace "root\CCM\Policy\Machine\ActualConfig" -Class CCM_ServiceWindow

        $ReadFromStringResult = $SMSScheduleMethods.ReadFromString( $CCMServiceWindow.Schedules )

        $ServiceWindow = $CCMServiceWindow | select -First 1

        $StartTime = ConvertFrom-ConfigurationManagerDateTime $ReadFromStringResult.TokenData[0].StartTime

        $ServiceDuration = New-Object System.TimeSpan `
                                      -ArgumentList @($ReadFromStringResult.TokenData[0].DayDuration, `
                                                      $ReadFromStringResult.TokenData[0].HourDuration, `
                                                      $ReadFromStringResult.TokenData[0].MinuteDuration, `
                                                      0)
        
        $NextRun = $StartTime.Add($ServiceDuration)

        switch ($ServiceWindow.ServiceWindowType)
        {
            0 {
                Write-Verbose "This is a Task Sequence maintenance window"
            }
            1 {
                Write-Verbose "This is a general maintenance window"
            }
        }   
        switch ($ReadFromStringResult.TokenData[0].__CLASS)
        {
            "SMS_ST_NonRecurring" {
                Write-Verbose "This maintenance window occurs only once on $($startTime) and lasts for $($ScheduleString.TokenData.HourDuration) hour(s) and $($ScheduleString.TokenData.MinuteDuration) minute(s)."
            }
            "SMS_ST_RecurInterval" {
                if ($ReadFromStringResult.TokenData.DaySpan -eq "1") {
                    $daily = "daily"
                } else {
                    $daily = "every $($ReadFromStringResult.TokenData.DaySpan) days"
                }
                        
                Write-Verbose "This maintenance window occurs $($daily)."
            }
            "SMS_ST_RecurWeekly" {
                switch ($ReadFromStringResult.TokenData.Day) {
                    1 {$weekday = "Sunday"}
                    2 {$weekday = "Monday"}
                    3 {$weekday = "Tuesday"}
                    4 {$weekday = "Wednesday"}
                    5 {$weekday = "Thursday"}
                    6 {$weekday = "Friday"}
                    7 {$weekday = "Saturday"}
                }
                
                New-Object System.DateTime 

                if ($ReadFromStringResult.TokenData[0].Day -le ((Get-Date).DayOfWeek.value__ +1)) {
                    $Days = [Math]::Abs($ReadFromStringResult.TokenData[0].Day - ((get-date).DayOfWeek.value__ + 1))
                } else {

                }

                
                                
                Write-Verbose "This maintenance window occurs every $($ReadFromStringResult.TokenData.ForNumberofWeeks) week(s) on $($weekday) and lasts $($ReadFromStringResult.TokenData.HourDuration) hour(s) and $($ReadFromStringResult.TokenData.MinuteDuration) minute(s) starting on $($StartTime)."
            }
            "SMS_ST_RecurMonthlyByWeekday" {
                switch ($ReadFromStringResult.TokenData.Day) {
                    1 {$weekday = "Sunday"}
                    2 {$weekday = "Monday"}
                    3 {$weekday = "Tuesday"}
                    4 {$weekday = "Wednesday"}
                    5 {$weekday = "Thursday"}
                    6 {$weekday = "Friday"}
                    7 {$weekday = "Saturday"}
                }
                switch ($ReadFromStringResult.TokenData.weekorder)
                {
                    0 {$order = "last"}
                    1 {$order = "first"}
                    2 {$order = "second"}
                    3 {$order = "third"}
                    4 {$order = "fourth"}
                }

                Write-Verbose "This maintenance window occurs every $($ReadFromStringResult.TokenData.ForNumberofMonths) month(s) on every $($order) $($weekday)"
            }

            "SMS_ST_RecurMonthlyByDate" {
                if ($ReadFromStringResult.TokenData.MonthDay -eq "0")
                { 
                    $DayOfMonth = "the last day of the month"
                }
                else
                {
                    $DayOfMonth = "day $($ReadFromStringResult.TokenData.MonthDay)"
                }
                Write-Verbose "This maintenance window occurs every $($ReadFromStringResult.TokenData.ForNumberofMonths) month(s) on $($DayOfMonth)."
                Write-Verbose "It lasts $($ReadFromStringResult.TokenData.HourDuration) hours and $($ReadFromStringResult.TokenData.MinuteDuration) minutes."
            }
        }

        return New-Object psobject -Property @{StartTime = $StartTime; Duration = $ServiceDuration; }
    }
}


function Test-CCMReceivingAdvertisements {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)

    process {
        $SoftwareDistributions = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\Policy\Machine\ActualConfig -Class CCM_SoftwareDistribution

        if ($SoftwareDistributions.Count -eq 0) {
            Write-Warning "[$ComputerName] no Software Distributions"
            return $false
        }

        $ScheduledMessages = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\Policy\Machine\ActualConfig -Class CCM_Scheduler_ScheduledMessage

        if ($ScheduledMessages.Count -eq 0) {
            Write-Warning "[$ComputerName] no Scheduled Messages"
            return $false
        }

        

        return $true
    }
}

function Repair-CCM {
    <#
    .Synopsis
       Attempts to detect and repair CCM
    #>
    [cmdletbinding()]
    param(# ComputerName of device 
          [Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName,
          # SiteCode of SCCM
          [string]$SiteCode,
          # ManagementPoint as a wild card string
          [string]$ManagementPoint)

    process {
        $Result = New-Object psobject -Property @{ Computer = $ComputerName;
                                                   Alive = $false;
                                                   DnsHostName = "";
                                                   DnsIpAddress = "";
                                                   DnsValid = $false;
                                                   SCCMValid = $false;
                                                   SCCMFailedAdvertisements = 0;
                                                   SCCMFailedUpdates = 0;
                                                   RPC = $false;
                                                   CCMSetupExists = $false;
                                                   DefaultAdminShare = $false;
                                                   LastMessage = ""; }


        [System.Net.IPHostEntry]$DnsHostEntry = $null
        [System.Net.IPAddress]$IPAddress = $null

        # check to see if computer is alive
        $Ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $PingReply = $Ping.Send($ComputerName)

            if ($PingReply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) {
                throw "unsuccessful ping"
            }

            $IPAddress = $PingReply.Address
            $Result.Alive = $true
            $Result.LastMessage = "Successful Ping"
        } catch [System.Net.NetworkInformation.PingException] {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$($ComputerName)] Ping Exception ($($_.Exception.Message))"
            return $Result
        } catch {
            $Result.LastMessage = $($_.Exception.Message)
            Write-Warning "[$($ComputerName)] $($_.Exception.Message)"
            return $Result
        }

        
        # check DNS to get HostName and IPAddress
        try {
            $DnsHostEntry = [System.Net.Dns]::GetHostEntry($ComputerName)
            
            # see if a hostname is valid
            $DnsHostName = ""
            if ($DnsHostEntry.HostName.Length -eq 0) {
                throw "HostName was not found in DNS"
            }

            # check to see if the "ComputerName" passed in is actually an IP address
            [System.Net.IPAddress]$ComputerNameIpAddress = $null
            if ([System.Net.IPAddress]::TryParse($ComputerName, [ref]$ComputerNameIpAddress)) { # ComputerName is IP address
                if ($IPAddress.Equals($ComputerNameIpAddress)) {
                    throw "ComputerName (as IP) does not match Ping IP Address"
                }
                if ($IPAddress.Equals(($DnsHostEntry.AddressList | select -First 1))) {
                    throw "ComputerName (as IP) does not match DNS IP Address"
                }
            } elseif ($DnsHostEntry.HostName -like "*$ComputerName*") { # ComputerName is HostName
                throw "DNS Record ($($DnsHostEntry.HostName)) does not match ComputerName"
            }

            # everything is good - lets take the results and move on
            $Result.DnsValid = $true
            $Result.DnsHostName = $HostName = $DnsHostName
            $Result.DnsIpAddress = $IPAddress
            $Result.LastMessage = "Dns Valid"
        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
            return $Result
        }


        # Check SMS (SCCM Server)
        try {

            $SMSRSystem = Request-SMSQuery -WQL "SELECT * FROM SMS_R_SYSTEM WHERE NAME = '$HostName' OR IPAddresses = '$IPAddress'"

            if (($SMSRSystem | measure).Count -eq 0) {
                throw "no object found in SCCM"
            } elseif (($SMSRSystem | measure).Count -gt 1) {
                # TODO: find the correct one and check for 3rd party/software updates

                throw "[$ComputerName] Multiple objects found in SCCM"
            }


            # check if Client is installed
            if (($SMSRSystem.Client -eq $null) -or ($SMSRSystem.Client -eq 0)) {
                $Result.LastMessage = "[$ComputerName] SCCM indicates that no Client is installed"
                Write-Warning $Result.LastMessage
            }

            $Result.LastMessage = "SMS Client installed"

            if ($SMSRSystem.Active -eq 0) {
                $Result.LastMessage = "[$ComputerName] SCCM indicates that the client is not Active"
                Write-Warning $Result.LastMessage
            }

            $Result.LastMessage = "SMS Client Active"

            # is the client marked for deletion
            if ($SMSRSystem.Obsolete -eq 1) {
                $Result.LastMessage = "[$ComputerName] SCCM indicates that the client is Obsolete"
                Write-Warning $Result.LastMessage
            }

            $Result.LastMessage = "SMS Client is not Obsolete"

            # check IP address match
            if ($SMSRSystem.IPAddresses -ne $IPAddress) {
                $Result.LastMessage = "[$ComputerName] The IP Address that was Pinged does not match SCCM IPAddresses[$($SMSRSystem.IPAddresses[0])]"
                Write-Warning $Result.LastMessage
                $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action DataDiscoveryFull
            }

            $Result.LastMessage = "SMS Client IP matches Pinged IP"

            # check hostname match
            if ($SMSRSystem.Name -ne $HostName) {
                $Result.LastMessage = ("[$ComputerName] DNS HostName {0} does not match SCCM Name {1}" -f $DnsHostEntry.HostName, $SMSRSystem.Name)
                Write-Warning $Result.LastMessage
                $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action DataDiscoveryFull
            }

            $Result.LastMessage = "SMS Client HostName matches DNS HostName"

            # check Advertisements
            $SMSClientAdvertisements = Request-SMSQuery -WQL "SELECT * FROM SMS_ClientAdvertisementStatus WHERE SMS_ClientAdvertisementStatus.ResourceId = $($SMSRSystem.ResourceId)"
            $Result.SCCMFailedAdvertisements = $SMSClientAdvertisements | ?{ $_.LastStateName -eq "Failed" } | Measure | select -ExpandProperty Count

            $Result.LastMessage = ("SMS indicates client is missing {0} Advertisements" -f $Result.SCCMFailedAdvertisements)

            # check Software updates
            $SMSUpdateComplianceStatus  = Request-SMSQuery -WQL "SELECT * FROM SMS_UpdateComplianceStatus WHERE SMS_UpdateComplianceStatus.MachineId = $($SMSRSystem.ResourceId)"
            $Result.SCCMFailedUpdates = $SMSUpdateComplianceStatus | ?{ $_.LastEnforcementMessageID -eq 11 } | measure | select -ExpandProperty Count

            $Result.LastMessage = ("SMS indicates client is missing {0} Software Updates" -f $Result.SCCMFailedUpdates)

            $Result.SCCMValid = $True
        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }

        <# check Active Directory for computer
        try {
            $ADComputer = $null

            $ADComputer = Get-ADComputer -LDAPFilter "(|(CN=$($Result.DnsHostName))(IPv4Address=$($Result.DnsIpAddress)))" `
                                         -Properties o, Enabled, CN, IPv4Address, DNSHostName, OperatingSystem, Location, DistinguishedName, LastLogonTimeStamp, MemberOf `
                                         -SearchBase ""

            if ($ADComputer -eq $null) {
                throw "HostName: $HostName IPAddress: $IPAddress not found in ActiveDirectory"
            }

            if (-not $ADComputer.Enabled) {
                throw "Active Directory indicates that the object is not enabled"
            }

            if ($ADComputer.DNSHostName -ne $DnsHostEntry.HostName) {
                throw "Active Directory indicates that the object does not match DnsHostName"
            }

            # check if DNS is updating Active Directory accurately
            [System.Net.IPAddress]$ADIpAddress = $null
            if ([System.Net.IPAddress]::TryParse($ADComputer.IPv4Address, [ref]$ADIpAddress)) {
                if (-not $IPAddress.Equals($ADIpAddress)) {
                    throw "Active Directory IPv4Address does not match Ping results"
                }
                if (-not ($DnsHostEntry.AddressList | select -First 1).Equals($ADIpAddress)) {
                    throw "Active Directory IPv4Address does not match Dns IP address"
                }
            } else {
                throw "Active Directory does not contain a valid IP Address"
            }

            # check for valid DnsHostNames
            if ($ADComputer.DNSHostName -ne $DnsHostEntry.HostName) {
                throw ("Active Directory DNSHostName ({0}) does not match discovered DNS HostName ({1})" -f $ADComputer.DNSHostName, $DnsHostEntry.HostName)
            }

            # check AD lastlogon
            if (([DateTime]::Now - [DateTime]::FromFileTime([Int64] $ADComputer.lastLogonTimestamp)).Days -gt 30) {
                throw "Active Directory indicates that the object has not been logged into in >30 days"
            }

            $Result.ActiveDirectoryValid = $true
            $Result.LastMessage = "Computer found in Active Directory"
        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
        }
        #>


        # check to see if we have access
        try {
            Test-Path "\\$ComputerName\admin$" -ErrorAction Stop | Out-Null
            $Result.DefaultAdminShare = $true
            
            Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction Stop | Out-Null
            $Result.RPC = $true
        } catch [System.UnauthorizedAccessException] {       
            $Result.LastMessage = "Unauthorized Access"     
            Write-Warning "[$ComputerName] Unauthorized Access"
            return $Result
        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($_.Exception.Message)"
            return $Result
        }


        # looking for ccmsetup folder existsance
        $CCMSetupFolderExists = $false
        if (Test-Path "\\$ComputerName\admin$\ccmsetup") {
            $CCMSetupFolderExists = $true
        }

        if (Test-Path "\\$ComputerName\admin$\system32\ccmsetup") {
            $CCMSetupFolderExists = $true
        }

        if ((Get-WmiObject -ComputerName $ComputerName -Class Win32_Directory -Filter "name = 'c:\\windows\\ccmsetup'" | measure).Count -eq 1) {
            $CCMSetupFolderExists = $True
        }
        
        if ((Get-WmiObject -ComputerName $ComputerName -Class Win32_Directory -Filter "name = 'c:\\windows\\system32\\ccmsetup'" | measure).Count -eq 1) {
            $CCMSetupFolderExists = $True
        }

        if ($CCMSetupFolderExists) {
            $Result.CCMSetupExists = $true
        } else {
            $Result.LastMessage = "ccmsetup folder not found - Installing"
            Write-Warning "[$ComputerName] ccmsetup folder not found - Installing"
            
            $InstallResults = Install-CCM $ComputerName

            return $Result
        }

        # see if there is anything in the setup log that indicates a failed install
        if (Test-Path "\\$ComputerName\admin$\ccmsetup\ccmsetup.log") {
            $SMSTrace = Get-Content "\\$ComputerName\admin$\ccmsetup\ccmsetup.log" | ConvertTo-SMSTrace

            # does the ccmsetup component indicate a successfull installation?
            if (($SMSTrace | ?{ ($_.component -eq "ccmsetup") -and ($_.logtext -eq "Installation succeeded.") } | measure).Count -eq 0) {
                Write-Verbose "[$ComputerName] ccmsetup log doesn't indicate a successfull installation."
                $Result.LastMessage = "ccmsetup log doesn't indicate a successfull installation"

                # $InstallResults = Install-CCM -ComputerName $ComputerName
                # return $Result
            }

            # does the last entry say its trying again?
            if (($SMSTrace | select -Last 1 | ?{ ($_.component -eq "ccmsetup") -and ($_.logtext -eq "Next retry in 10 minute(s)...") } | measure).Count -eq 1) {
                $Result.LastMessage = "ccmsetup log indicates a install retry"

                Write-Verbose "[$ComputerName] ccmsetup log indicates a install retry"

                # $InstallResults = Install-CCM -ComputerName $ComputerName
                # return $Result
            }
        }


        # check CCM Services
        try {
            # SMS Agent Host
            $CCMExecService = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter "Name='CCMExec'" -ErrorAction Stop

            if ($CCMExecService -eq $null) {
                throw "ccmexec service not found"
            }

            # make sure it automatically starts
            if ($CCMExecService.StartMode -ne "Auto") {
                Write-Verbose "[$($ComputerName)] Setting CCMExec StartMode to Automatic"
                Set-Service -ComputerName $ComputerName -Name CcmExec -StartupType Automatic
            }

            # start service if its not running
            if ($CCMExecService.State -ne "Running") {
                Write-Verbose "[$($ComputerName)] Starting CCMExec Service"

                if (-not (Set-CCMServiceState -WmiService $CCMExecService -NewState Running -TimeOutSpan ([System.TimeSpan]::FromSeconds(15)) -ErrorAction Stop)) {
                    throw "Unable to start $($CCMExecService.DisplayName) service"
                }
            }

            # SMS Task Sequence Agent
            $SMSTSMgrService = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter "Name='smstsmgr'" -ErrorAction Stop

            if ($SMSTSMgrService -eq $null) {
                throw "ccmexec service not found"
            }

        } catch {
            $Result.LastMessage = $_.Exception.Message

            Write-Warning "[$ComputerName] $($Result.LastMessage)"
            $InstallResults = Install-CCM $ComputerName

            return $Result
        }
        
        # check CCM WMI Namespaces and components
        try {
            # check for CCMClient WMI namespace
            $CCMClient = Get-WmiObject -ComputerName $ComputerName -Class CCM_Client -Namespace root\ccm -List -ErrorAction Stop
            
            
            # check for CCM Components WMI Namespace    
            $CCMInstalledComponents = gwmi -ComputerName $ComputerName `
                                           -Namespace root\ccm `
                                           -Class CCM_InstalledComponent `
                                           -ErrorAction Stop
            # do components exist?
            if ($CCMInstalledComponents.Count -eq 0) {
                throw "required components are not configured properly"
            }

            $CCMComponentClientConfig = Get-WmiObject -ComputerName $ComputerName `
                                                      -Namespace "root\ccm\policy\machine" `
                                                      -Class ccm_componentclientconfig `
                                                      -ErrorAction Stop
            # are there 9 components enabled?
            if (($CCMComponentClientConfig | ?{ $_.Enabled -eq $True } | measure).Count -lt 9) {
                throw "Client does not have required components installed"
            }

            
            # check SMS_Client WMI Namespace
            $SMSClient = Get-WmiObject -ComputerName $ComputerName -Class sms_client -Namespace root\ccm -List -ErrorAction Stop
            
            # check SiteCode
            if ($SMSClient.GetAssignedSite().sSiteCode -ne $SiteCode) {
                throw "invalid SiteCode: $($SMSClient.GetAssignedSite().sSiteCode)"
            }

            # check ClientVersion
            if ($SMSClient.GetInstances().ClientVersion -eq "0.0.0.0") {
                throw "invalid Client version: $($SMSClient.GetInstances().ClientVersion)"
            }


            # check management point
            $SMSAuthority = gwmi -ComputerName $ComputerName -Namespace root\ccm -Class SMS_Authority -ErrorAction Stop

            if ($SMSAuthority.CurrentManagementPoint -notlike $ManagementPoint) {
                throw "Client Management Point ($($SMSAuthority.CurrentManagementPoint) does not match $ManagementPoint"
            }

            # check for GUID
            $CCMClient = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm -Class CCM_Client -ErrorAction Stop

            if (-not $CCMClient.ClientId) {
                throw "Client does not have a GUID"
            }

            # check certificates
            $SMSCertificates = Get-SMSCertificates -Computer $ComputerName
            if ($SMSCertificates | ?{ $_.Subject -notlike "*$HostName*" }) {
                Write-Warning "[$ComputerName] invalid certificates"
                if (Remove-SMSCertificates -Computer $ComputerName) {
                    $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action CertificateMaintenance
                } else {
                    throw "unable to remove invalid SMS Certificates"
                }
            }
        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($Result.LastMessage)"
            #Write-Warning "[$($ComputerName)] CCM_InstalledComponent Namespace Missing - invoking repair"
            $CCMRepair = Invoke-CCMRepair $ComputerName

            return $Result
        }

        # check if client is receiving advertisements
        try {
            $SoftwareDistributions = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\Policy\Machine\ActualConfig -Class CCM_SoftwareDistribution -ErrorAction Stop
            if ($SoftwareDistributions.Count -eq 0) {
                throw "no Software Distributions found"
            }

            $ScheduledMessages = gwmi -ComputerName $ComputerName -Namespace ROOT\CCM\Policy\Machine\ActualConfig -Class CCM_Scheduler_ScheduledMessage -ErrorAction Stop
            if ($ScheduledMessages.Count -eq 0) {
                throw "no Scheduled Messages found"
            }

        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($Result.LastMessage)"
            #Write-Warning "[$($ComputerName)] CCM_InstalledComponent Namespace Missing - invoking repair"
            $CCMPolicyReset = Reset-CCMPolicy -ComputerName $ComputerName

            return $Result
        }
        
        # Check Last time Hardware Inventory was ran
        $HWInvTimeSpan = New-TimeSpan -Start (Get-CCMLastHWInventory -ComputerName $ComputerName) -End (Get-Date)
        if ($HWInvTimeSpan.Days -ge 3) {
            Write-Verbose "[$ComputerName] CCM Repair - last HW Inventory Cycle was $($HWInvTimeSpan.Days) day(s) ago"
            $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action HWInventory
        }

        # Check Last time Software Inventory was ran
        $SWInvTimeSpan = New-TimeSpan -Start (Get-CCMLastSWInventory -ComputerName $ComputerName) -End (Get-Date)
        if ($SWInvTimeSpan.Days -ge 3) {
            Write-Verbose "[$ComputerName] CCM Repair - last SW Inventory Cycle was $($SWInvTimeSpan.Days) day(s) ago"
            $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action SWInventory
        }

        # checking cache
        try {
            # TODO - detect orphaned items
            $CacheConfig = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\softmgmtAgent -Class CacheConfig
            if ($CacheConfig.Location -eq "") {
                $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action SWUpdateDeploy
                throw "CCM Cache location not set"
            }

            $CacheInfoEx = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\softmgmtAgent -Class CacheInfoEx
            if ($CacheInfoEx.Count -eq 0) {
                $CCMAction = Invoke-CCMAction -ComputerName $ComputerName -Action SWUpdateDeploy
                throw "Cache is empty"
            }
        } catch {
            $Result.LastMessage = $_.Exception.Message
            Write-Warning "[$ComputerName] $($Result.LastMessage)"
            
            Invoke-CCMAction -ComputerName $ComputerName -Action DataDiscoveryFull

            return $Result
        }

         # remove any waiting for content that may be preventing other items to be installed
        $CCMRemoveRunningJobs = Remove-CCMRunningJobs -ComputerName $ComputerName -JobState WaitingContent

        # install any software updates
        # Invoke-CCMSoftwareUpdates -ComputerName $ComputerName | Out-Null

        return $Result
     }
}

function Install-CCM {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName,
          [string]$CCMSetupPath)

    process {
        $Process = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "name = 'ccmsetup.exe'"
        if ($Process) {
            Write-Verbose "[$ComputerName] ccmsetup process has already started"

            $CCMSetupService = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter "name='ccmsetup'"
            if (($CCMSetupService -ne $null) -and ($CCMSetupService.State -ne "Running")) {
                $CCMSetupService.Start()
            }

            $CCMService = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter "name='ccmexec'"
            if (($CCMService -ne $null) -and ($CCMService.State -ne "Running")) {
                $CCMService.Start()
            }

            return $false
        }

        $RunningProc = $null

        try {
            if (Test-Path "\\$ComputerName\admin$\ccmsetup\ccmsetup.exe" -ErrorAction Ignore ) {
                $RunningProc = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList "C:\windows\ccmsetup\ccmsetup.exe" -ErrorAction Stop
            } elseif (Test-Path "\\$ComputerName\admin$\System32\ccmsetup\ccmsetup.exe" -ErrorAction Ignore) {
                $RunningProc = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList "C:\windows\system32\ccmsetup\ccmsetup.exe" -ErrorAction Stop
            } elseif ((Get-WmiObject -ComputerName $ComputerName -Class Win32_Directory -Filter "name = 'c:\\windows\\ccmsetup'" | measure).Count -eq 1) {
                $RunningProc = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList "C:\windows\ccmsetup\ccmsetup.exe" -ErrorAction Stop
            } elseif ((Get-WmiObject -ComputerName $ComputerName -Class Win32_Directory -Filter "name = 'c:\\windows\\system32\\ccmsetup'" | measure).Count -eq 1) {
                $RunningProc = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList "C:\windows\system32\ccmsetup\ccmsetup.exe" -ErrorAction Stop
            }
        } catch {
            Write-Error "[$ComputerName] unable to start ccmsetup.exe"

            Remove-PSDrive -Name Z -ErrorAction SilentlyContinue | Out-Null

            # New-PSDrive -Name "Z" -Description "[$ComputerName] map to copy ccmsetup" -PSProvider FileSystem -Root "\\$ComputerName\c$" -Credential $Credentials
            New-PSDrive -Name "Z" -Description "[$ComputerName] map to copy ccmsetup" -PSProvider FileSystem -Root "\\$ComputerName\c$"
            if (Test-Path Z:\) {
                Copy-Item -Path $CCMSetupPath -Destination "Z:\Windows\temp"
                $RunningProc = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList "C:\windows\temp\ccmsetup.exe"
            } else {
                Write-Warning "[$ComputerName] Unable to map temp drive"
            }

            Remove-PSDrive -Name Z
        }

        # Values for ReturnValue??? https://msdn.microsoft.com/en-us/library/aa389347%28v=vs.85%29.aspx
        if ($RunningProc -and $RunningProc.ReturnValue -eq 0) {
            return $true
        }

        return $false
    }
}

function Uninstall-CCM {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$ComputerName)
    process {

        <#
        Write-Warning "NEEDS Testing"
        return
        $CCMSetupPaths = @("\\$ComputerName\admin`$\ccmsetup\ccmsetup.exe", "\\$ComputerName\admin`$\system32\ccmsetup\ccmsetup.exe")

        $ctr = 0
        $FoundSetupPath = $false
        do {
            $CCMSetupPath = $CCMSetupPaths[$ctr]

            if (Test-Path $CCMSetupPath) {
                $FoundSetupPath = $True
            }
            $ctr++
        } while (!$FoundSetupPath -and ($ctr -lt $CCMSetupPaths.Count))

        if (-not $FoundSetupPath) {
            $CCMSetupPath = "\\$ComputerName\admin`$\system32\ccmsetup\ccmsetup.exe"

            Write-Warning "[$ComputerName] CCM Repair - unable to find ccmsetup for uninstall - do it yourself"
            return $false
        }

        #>
        
        if (-not (Test-Path "\\$ComputerName\admin`$\ccmsetup\ccmsetup.exe")) {
            return $false
        }

        try {
            $CCMExecService = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter "Name='CCMExec'" -ErrorAction Stop

            # attempt to stop service
            $Attempts = 0
            while (($CCMExecService.State -eq "Running") -and ($Attempts -lt 5)) {
                $CCMExecService.StopService()
                $Attempts += 1
            }
            if ($CCMExecService.State -eq "Running") {
                # try a different method for some reason
                Get-Service -ComputerName $ComputerName -Name CcmExec -ErrorAction Stop | Stop-Service -Force -ErrorAction Stop
                throw "unable to stop service"
            }


            # wait for complete service stop
            $Attempts = 0
            while (($CCMExecService.State -eq "Stop Pending") -and ($Attempts -lt 5)) {
                Start-Sleep -Seconds 1
                $Attempts += 1
            }
            if ($CCMExecService.State -eq "Stop Pending") {
                throw "Service stop Pending"
            }

        } catch {
            Write-Warning "[$ComputerName] unable to stop ccmexec service"
            return $false
        }

        try {
            # uninstall
            $UninstallProcess = Invoke-WmiMethod -ComputerName $ComputerName -Class win32_process -Name create -ArgumentList "C:\$ComputerName\admin`$\ccmsetup\ccmsetup.exe /uninstall"

            if ($UninstallProcess.ProcessId -eq $null) {
                throw "Unable to start uninstall process"
            }
        } catch {
            Write-Warning "[$ComputerName] unable to start uninstall process"
            return $false
        }

        $RunningProcess = Get-Process -ComputerName $ComputerName -Id $UninstallProcess.ProcessId

        if ($RunningProcess) {
            return $True
        }

        return $false
    }
}




function ConvertTo-SMSTrace {
    [cmdletbinding()]
    param([Parameter(Mandatory=$True,
                     ValueFromPipeline=$true)]
          [string]$Log)
          
    process {
        $SMSTrace = New-Object psobject -Property @{ LogText = "";
                                                     Time = "";
                                                     Date = "";
                                                     DateTime = (New-Object datetime);
                                                     component = "";
                                                     context = "";
                                                     Type = 0;
                                                     Thread = 0;
                                                     File = ""; }

        if ($Log -match "LOG\[(.*?)\]") {
            $SMSTrace.logtext = $Matches[1]
        }

        $LogTimeStr = $null;
        $LogDateStr = $null;

        if ($Log -match "time=`"(.*?)`"") {
            $SMSTrace.time = $Matches[1]
            $LogTimeStr = $Matches[1]
        }

        if ($Log -match "date=`"(.*?)`"") {
            $SMSTrace.date = $Matches[1]
            $LogDateStr = $Matches[1]
        }

        if ($LogDateStr -ne $null -and $LogTimeStr -ne $null) {
            #variable for directory date
            [datetime]$LogDate = New-Object DateTime

            $DateTimeStr = $LogDateStr + " " + $LogTimeStr.Substring(0,$LogTimeStr.IndexOf("+"))
            
            #check that directory name could be parsed to DateTime
            if([DateTime]::TryParse($DateTimeStr,[ref]$LogDate)) {
                $SMSTrace.DateTime = $LogDate
            }
        }


        if ($Log -match "component=`"(.*?)`"") {
            $SMSTrace.component = $Matches[1]
        }

        if ($Log -match "context=`"(.*?)`"") {
            $SMSTrace.context = $Matches[1]
        }

        if ($Log -match "type=`"(.*?)`"") {
            $SMSTrace.type = [int]($Matches[1])
        }

        if ($Log -match "thread=`"(.*?)`"") {
            $SMSTrace.thread = [int]($Matches[1])
        }

        if ($Log -match "file=`"(.*?)`"") {
            $SMSTrace.file = $Matches[1]
        }

        return $SMSTrace
    }    
}

