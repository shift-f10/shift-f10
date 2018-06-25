function Get-psEventLog {    
    
<#    
    
    .SYNOPSIS

    Ensure Audit Process Creation in GP setting is enabled in path Computer
    Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking
    
    
    Added process commandline parsing.  Must enable in GPO, see https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
    Alternatively you can enter a REG_DWORD value of 1 to key ProcessCreationIncludeCmdLine_Enabled in path HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit

    Author: Ramil Flores (@shift-f10)
    License: https://opensource.org/licenses/BSD-3-Clause
    Tested Version: Powershell 5.0
    
    .DESCRIPTION

#>    
    # Change or remove the MaxEvents value to the number of items you want to see
    # or change the FilterXPath to a more defined filter
    # for some reason, Google Chart can map 150 events or else the chart fails to load.
    $logs = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" -MaxEvents 150
    
    # Initialize the array to store output
    $out = @()

    # Loop through the matching records, parse the data and store it in the array
    foreach ($entries in $logs) {

        #return date and time inf
        $eventDate = get-date $entries.TimeCreated -Format d
        $eventTime = get-date $entries.TimeCreated -Format t

        #return PID
        $getpid = $entries.message -split "\r\n" | Select-String -SimpleMatch "New Process ID:"
        [array]$hexPID = $getpid -split ":"
        $ProcID = [System.Convert]::ToInt64($hexPID[1].trim(),16)

        #return Process Name
        $getproc = $entries.message -split "\r\n" | Select-String -SimpleMatch "New Process Name:"
        [array]$arrProc = $getproc -split "\t"
        $ProcName = $arrProc[2] -split "\\"
        $ProcName = $ProcName[$ProcName.Length - 1]

        #return Parent PID
        $getppid = $entries.message -split "\r\n" | Select-String -SimpleMatch "Creator Process ID:"
        [array]$hexPPID = $getppid -split ":"
        $PPID = [System.Convert]::ToInt64($hexPPID[1].trim(),16)

        #return Parent Process Name
        $getpproc = $entries.message -split "\r\n" | Select-String -SimpleMatch "Creator Process Name:"
        [array]$arrPProc = $getpproc -split "\t"
        $PProcName = $arrPProc[2] -split "\\"
        $PProcName = $PProcName[$PProcName.Length - 1]

        #return Account Name
        $getAcctinfo = $entries.message -split "\r\n" | Select-String -SimpleMatch "Account Name:"
        [array]$arrAcct = $getAcctinfo -split ":"
        $Account = $arrAcct[1].trim()

        #return Domain
        $getDomain = $entries.message -split "\r\n" | Select-String -SimpleMatch "Account Domain:"
        [array]$arrDomain = $getDomain -split ":"
        $Domain = $arrDomain[1].trim()

        #return commandline
        $getcmdline = $entries.message -split "\r\n" | Select-String -SimpleMatch "Process Command Line:"
        [array]$arrcmd = $getcmdline -split "\t"
        $cmd = $arrcmd[2]
        if ($ProcName -eq "dllhost.exe") {
            [array]$cid = $cmd -split ":"
            $cid2 = $cid[2]
            $regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\$cid2"
            $paramout = (Get-ItemProperty -Path "Registry::$regPath").'(default)'
            $ProcName = "dllhost.exe ($paramout)"
        }


        #check if process still running
        if ((Get-Process -Id $ProcID -ErrorAction SilentlyContinue) -eq $null ) {
            $running = $false
        } else {
            $running = $true
        }



        $out += New-Object -TypeName psobject -Property @{ Date=$eventDate; Time=$eventTime; PID=$ProcID; Process=$ProcName; Cmd=$cmd; Running=$running; Domain=$Domain; User=$Account; Parent=$PPID; ParentProcess=$PProcName}

    }
    $html = "
        <html>
        <head>
        <title>Event Process Tracking for $env:Computername generated on $(get-date)</title>
            <script type=`"text/javascript`" src=`"https://www.gstatic.com/charts/loader.js`"></script>
            <script type=`"text/javascript`">
                google.charts.load('current', {packages:[`"orgchart`"]});
                google.charts.setOnLoadCallback(drawChart);

                function drawChart() {
                var data = new google.visualization.DataTable();
                var data = new google.visualization.DataTable();
                data.addColumn('string', 'PID');
                data.addColumn('string', 'PPID');
                data.addColumn('string', 'Information');
                data.addRows([`r`n" 

    foreach ($i in $out)  { $html += "`t`t`t`t`t['$($i.PID)', '$($i.Parent)', '$($i.Process)'],`n" }

    $html += "`t`t`t`t`t['EventLog Mapper','','Charting Process 4688 history from eventlog.']]);
                var chart = new google.visualization.OrgChart(document.getElementById('chart_div'));
                chart.draw(data, {allowHtml:true});}
            </script>
        </head>
        <body>
            <div id=`"chart_div`"></div>`n"

    $htmlfrag = $out | select Date, Time, PID, Process, Running, Domain, User, Parent, ParentProcess, Cmd | ConvertTo-Html -Fragment

    $html += "`t`t$htmlfrag"

    $html += "</body>"

    $html


   }

#change file path where to save output.
#also be aware, Chrome doesn't seem to load the Chart locally, I have not dug into it more but it could be a trust setting
#as Internet Explorer loads the file, you just have to click Enable Active X content.

Get-psEventLog | Out-File -FilePath "C:\change\path\to\file.htm"
