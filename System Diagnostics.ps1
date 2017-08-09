########################################################
# Created by Micah Wells
# Based on a script by Prashant Dev Pandey
# pandey.nic@rediffmail.com
# prashantdev.pandey@gmail.com
# v1.5 2017-08-08
# Released on GitHub under GNU GPL V3
# https://github.com/mythicalmw/System-Diags
# micahawells@gmail.com
##########################################################
#System Diagnostics for Windows Server 2012/8.1 and above#
##########################################################
do {
    do {
        write-host ""
        write-host "A - Run Analysis"
        write-host "B - Compress/ZIP Results"
        write-host ""
        write-host "X - Exit"
        write-host ""
        write-host -nonewline "Type your choice and press Enter: "
        
        $choice = read-host
        
        write-host ""
        
        $ok = $choice -match '^[abx]+$'
        
        if ( -not $ok) { write-host "Invalid selection" }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
        "A"
        {
        CLS
Write-Host "Running Analysis. Please Wait..."

#Create Scripts folder if it does not exist
$path = "C:\Scripts\Reports"
If(!(test-path $path))
{
New-Item -ItemType Directory -Force -Path $path | Out-Null
} 

#Start creating output report
$Outputreport=""
$Outputreport +="<style>TABLE{ border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;align:center;width:100%;}
TH{border-width: 1px;background-color: lightblue;bgcolor=blue;padding: 3px;border-style: solid;border-color: black;}
TD{border-width: 1px;color: white;background-color: gray;padding: 3px;border-style: solid;border-color: black;}
 
h1{text-shadow: 1px 1px 1px #000,3px 3px 5px blue; text-align: center;font-style: calibri;font-family: Calibri;</style>"
 

## Get Host Name
$Hostname = hostname | Out-String
 
## Get System Make
$Systemmake = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer

## Get System Model
$Systemmodel = (Get-WmiObject -Class Win32_ComputerSystem).Model

## Get Serial Number
$Serial = (Get-WmiObject -Class Win32_BIOS).SerialNumber

## Bet BIOS Version
$BIOSversion = (Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion

## Get version
$Version = (Get-WmiObject -class Win32_OperatingSystem).Caption | Out-String
 
## Get Uptime
$UPTIME=Get-WmiObject Win32_OperatingSystem
$up = [Management.ManagementDateTimeConverter]::ToDateTime($UPTIME.LastBootUpTime) | Out-String
 
## Get Disk Spaces
$Disk = Get-WmiObject Win32_logicaldisk -ComputerName LocalHost -Filter "DriveType=3" |select -property DeviceID,@{Name="Size(GB)";Expression={[decimal]("{0:N0}" -f($_.size/1gb))}},@{Name="Free Space(GB)";Expression={[decimal]("{0:N0}" -f($_.freespace/1gb))}},@{Name="Free (%)";Expression={"{0,6:P0}" -f(($_.freespace/1gb) / ($_.size/1gb))}}|ConvertTo-Html
 
 
## Get CPU Utilization
$CPU_Utilization = Get-Process|Sort-object -Property CPU -Descending | Select -first 5 -Property ID,ProcessName,@{Name = 'CPU In (%)';Expression = {$TotalSec = (New-TimeSpan -Start $_.StartTime).TotalSeconds;[Math]::Round( ($_.CPU * 100 /$TotalSec),2)}},@{Expression={$_.threads.count};Label="Threads";},@{Name="Mem Usage(MB)";Expression={[math]::round($_.ws / 1mb)}},@{Name="VM(MB)";Expression={"{0:N3}" -f($_.VM/1mb)}}|ConvertTo-Html
#$proc =get-counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 2
#$cpu=($proc.readings -split ":")[-1]
#$CPU_Utilization = [System.Math]::Round($cpu, 2) | Out-String
 
 
## Get Each Processor Utilization
$arr=@()
$ProcessorObject=gwmi win32_processor
foreach($processor in $ProcessorObject)
{
   $arr += $processor.Caption
   $arr += $processor.LoadPercentage
}
 
## Security Patches
$SecPatch = get-hotfix -Description "Security Update" |sort "Description" -desc | select Description,installedon -first 1 | Out-String
 
## RAM Usage
$Private:perfmem = Get-WmiObject -namespace root\cimv2 Win32_PerfFormattedData_PerfOS_Memory
$Private:totmem = Get-WmiObject -namespace root\cimv2 CIM_PhysicalMemory
[Int32]$Private:totalcapacity = 0
foreach ($Mem in $totmem)
{
$totalcapacity += $Mem.Capacity / 1Mb
}
#Get-WmiObject Win32_PhysicalMemory | ForEach-Object {$totalcapacity += $_.Capacity / 1Mb}
 
$Private:tmp = New-Object -TypeName System.Object
$tmp | Add-Member -Name CapacityMB -Value $totalcapacity -MemberType NoteProperty
$tmp | Add-Member -Name AvailableMB -Value $perfmem.AvailableMBytes -MemberType NoteProperty
$ram_usage = $tmp |ConvertTo-Html
 
## Physical Memory
function Get-MemoryUsage ($ComputerName=$ENV:ComputerName) {
if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
$ComputerSystem = Get-WmiObject -ComputerName $ComputerName -Class Win32_operatingsystem -Property TotalVisibleMemorySize, FreePhysicalMemory
$MachineName = $ComputerSystem.CSName
$FreePhysicalMemory = ($ComputerSystem.FreePhysicalMemory) / (1mb)
$TotalVisibleMemorySize = ($ComputerSystem.TotalVisibleMemorySize) / (1mb)
$TotalVisibleMemorySizeR = "{0:N2}" -f $TotalVisibleMemorySize
$TotalFreeMemPerc = ($FreePhysicalMemory/$TotalVisibleMemorySize)*100
$TotalFreeMemPercR = "{0:N2}" -f $TotalFreeMemPerc
# print the machine details:
"<table border=1 width=100>"
"<tr><th>RAM</th><td>$TotalVisibleMemorySizeR GB</td></tr>"
"<tr><th>Free Physical Memory</th><td>$TotalFreeMemPercR %</td></tr>"
"</table>"
 
}}
$PhyMem = Get-MemoryUsage
$Hotfix=(get-hotfix | sort installedon)|select -first 5 HotFixID,InstalledBy,InstalledOn,Description|ConvertTo-Html
$Processor_Counter=Get-Counter "\Processor(_total)\% Processor Time"|ConvertTo-Html
$Total_Threads=(Get-Process |Select-Object -ExpandProperty Threads).Count
## Paging
 
#function Get-PageFile {
#param(
#    [string]$computer="."
#)    
#        Get-WmiObject -Class Win32_PageFileUsage  -ComputerName $computer |
#        Select  @{Name="File";Expression={ $_.Name }},
#        @{Name="Base Size(MB)"; Expression={$_.AllocatedBaseSize}},
#        @{Name="Peak Size(MB)"; Expression={$_.PeakUsage}},  
#        TempPageFile
#  }
 
$PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory  |
Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
$ht = @{}
$ht.Add('Total_Ram(GB)',$PhysicalRAM)
$OSRAM = gwmi Win32_OperatingSystem  |
foreach {$_.TotalVisibleMemorySize,$_.FreePhysicalMemory}
$ht.Add('Total Visable RAM GB',([Math]::Round(($OSRAM[0] /1MB),2)))
$ht.Add('Available_Ram(GB)',([Math]::Round(($OSRAM[1] /1MB),2)))
$RAM = New-Object -TypeName PSObject -Property $ht|ConvertTo-Html
#$Paging1=Get-PageFile|ConvertTo-Html
#$Paging =  Get-WMIObject Win32_PageFileSetting |  select Name, InitialSize, MaximumSize|ConvertTo-Html
 
#$Available_Bytes=Get-Counter -Counter "\Memory\Available Bytes"|Select -ExpandProperty CounterSamples|Select CookedValue |ft -HideTableHeaders|out-string
#$att=Get-Counter -Counter "\Memory\Committed Bytes"|Select -ExpandProperty CounterSamples|Select CookedValue |ft -HideTableHeaders|out-string
#$Comitted_Bytes="{0:N0}" -f (($att.trim())/1024/1024)
#$Handle_Count=Get-Counter -Counter "\Process(_Total)\Handle Count"|Select -ExpandProperty CounterSamples|Select CookedValue |ft -HideTableHeaders|out-string
#$Thread_Count=Get-Counter -Counter "\Process(_Total)\Thread Count"|Select -ExpandProperty CounterSamples|Select CookedValue |ft -HideTableHeaders|out-string
#$ftt=Get-Counter -Counter "\memory\Pool Paged Bytes"|Select -ExpandProperty CounterSamples|Select CookedValue |ft -HideTableHeaders|out-string
#$Pool_Paged="{0:N0}" -f (($ftt.trim())/1024/1024)
#$dtt=Get-Counter -Counter "\memory\Pool Nonpaged Bytes"|Select -ExpandProperty CounterSamples|Select CookedValue |ft -HideTableHeaders|out-string
#$Pool_NonPaged="{0:N0}" -f (($dtt.trim())/1024/1024)
#$Total_process=(get-process).count
 
$Outputreport +="<HTML><HEAD><TITLE>ANALYSIS FOR "+$Systemmake+" "+$Systemmodel+" "+$Serial+"</TITLE></HEAD><BODY>"
 
$Outputreport +="<table border=1 ><tr><td>"
$Outputreport +="<table border=1 width=100%>"
$Outputreport +="<tr><th><B>Hostname</B></th><td>"+$Hostname+"</td></tr>"
$Outputreport +="<tr><th><B>Device Manufacturer</B></th><td>"+$Systemmake+"</td></tr>"
$Outputreport +="<tr><th><B>Device Model</B></th><td>"+$Systemmodel+"</td></tr>"
$Outputreport +="<tr><th><B>Device Serial Number</B></th><td>"+$Serial+"</td></tr>"
$Outputreport +="<tr><th><B>BIOS Version</B></th><td>"+$BIOSversion+"</td></tr>"
$Outputreport +="<tr><th><B>Version</B></th><td>"+$Version+"</td></tr>"
$Outputreport +="<tr><th><B>Last Reboot</B></th><td>"+$up+"</td></tr>"
$Outputreport +="<tr><th><B>Physical Memory</B></th><td>"+$PhysicalRAM+"GB RAM</td></tr></td></tr>"
#$Outputreport +="<tr><td><tr><th><B>System</B></th></tr><tr><th>Total Handles</th><td>"+$Handle_Count.trim()+"</td></tr><tr><th>Total Thread</th><td>"+$Thread_Count.trim()+"</td></tr><tr><th>Total Process</th><td>"+$Total_process+"</td></tr><tr><th>Commit(MB)</th><td>"+$Comitted_Bytes.trim()+"</td></tr></td>"
#$Outputreport +="<td><tr><th><B>Kernel Memory(MB)</B></th></tr><tr><th>Paged</th><td>"+$Pool_Paged.trim()+"</td></tr><tr><th>Non Paged</th><td>"+$Pool_NonPaged.trim()+"</td></tr></td></tr>"
$Outputreport += "</table>"
$Outputreport += "</table>"
$Outputreport +="</br>"
$Outputreport +="</br>"
$Outputreport +="<table border=1 width=50%>"
$Outputreport +="<tr><th><B>Disk Size</B></th><td>"+$Disk+"</td></tr>"
$Outputreport +="<tr><th><B>Top5 Process</B></th><td>"+$CPU_Utilization+"</td></tr>"
#$Outputreport +="<tr><th><B>Ram_Usage</B></th><td>"+$ram_usage+"</td></tr>"
#$Outputreport +="<tr><th><B>Physical Memory</B></th><td>"+$PhyMem+"</td></tr>"
#$Outputreport +="<tr><th><B>Processor Counter</B></th><td>"+$Processor_Counter+"</td></tr>"
$Outputreport +="<tr><th><B>Last 5 HotFix</B></th><td>"+$Hotfix+"</td></tr>"
#$Outputreport +="<tr><th><B>Paging</B></th><td>"+$Paging+"</td></tr>"
#$Outputreport +="<tr><th><B>No Of Threads</B></th><td>"+$Total_Threads+"</td></tr>"
$Outputreport +="<tr><th><B>View Detailed Event Log Error Information:</B></th><td><table border=1><tr><th>View System Event Log</th><th>View Application Event Log</th></tr><tr><td><a href='file:///c:\scripts\Reports\SystemLog.html' target='_blank'>System Event Log</a></td><td><a href='file:///c:\scripts\Reports\ApplicationLog.html' target='_blank'>Application Event Log</a></td></tr></table></tr>"
$Outputreport += "</table></BODY></HTML>"
$Outputreport | out-file C:\Scripts\Reports\Windows_Server_Health_Status.html

##Output full MSINFO32 to NFO file
msinfo32 /nfo C:\Scripts\Reports\MSInfo32.nfo

#Exporting Event Logs to HTML pages
$style = "<style>"
$style = $style + "Body{background-color:white;font-family:Arial;font-size:10pt;}"
$style = $style + "Table{border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}"
$style = $style + "TH{border-width: 1px; padding: 2px; border-style: solid; border-color: black; background-color: #cccccc;}"
$style = $style + "TD{border-width: 1px; padding: 5px; border-style: solid; border-color: black; background-color: white;}"
$style = $style + "</style>"
 

#Configuring Date 
$date = get-date -format M.d.yyyy
 
$now = get-date
$subtractDays = New-Object System.TimeSpan 30,0,0,0,0
$then = $Now.Subtract($subtractDays)

#System Event Logs 
$systemErrors = Get-EventLog -Computername localhost -LogName system -After $then -Before $now -EntryType Error |
select EventID,Message,Source,TimeGenerated
 
$systemhtml = $systemErrors | ConvertTo-HTML  -Property *,@{Label="More Information";Expression={"<a href='https://www.google.com/#q=Windows+System+Event+Log+Error+$($_.EventID)' target='_blank'>Find more...</a>"}} -head $style  

Add-Type -AssemblyName System.Web
[System.Web.HttpUtility]::HtmlDecode($systemhtml) | Out-File "C:\Scripts\Reports\SystemLog.html"

##Application Event Logs
$applicationErrors = Get-EventLog -Computername localhost -LogName application -After $then -Before $now -EntryType Error |
select EventID,Message,Source,TimeGenerated
 
$applicationhtml = $applicationErrors | ConvertTo-HTML  -Property *,@{Label="More Information";Expression={"<a href='https://www.google.com/#q=Windows+Application+Event+Log+Error+$($_.EventID)' target='_blank'>Find more...</a>"}} -head $style  

#Copy memory dumps
If(test-path $env:SystemRoot\MEMORY.DMP)
{
Copy-Item $env:SystemRoot\MEMORY.DMP "C:\Scripts\Reports"
}

Add-Type -AssemblyName System.Web
[System.Web.HttpUtility]::HtmlDecode($applicationhtml) | Out-File "C:\Scripts\Reports\ApplicationLog.html"
start C:\Scripts\Reports\Windows_Server_Health_Status.html
CLS
Write-Host "Analysis Complete."
        }
        
        "B"
        {
            $source = "C:\Scripts\Reports"

            $destination = "$env:USERPROFILE\Desktop\Results.zip"

            If(Test-path $destination) {Remove-item $destination}

            Add-Type -assembly "system.io.compression.filesystem"

            [io.compression.zipfile]::CreateFromDirectory($Source, $destination)

            CLS

            Write-Host "File created as $destination"
            
        }

    }
} until ( $choice -match "X" ) 