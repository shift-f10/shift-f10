function Get-psEventLog-visjs {    
    
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
    $logs = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" -MaxEvents 60
    
    # Initialize the array to store output
    $out = @()
    $c = 0

    # Loop through the matching records, parse the data and store it in the array
    foreach ($entries in $logs) {
        $c = $c + 1

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
            if ($cid2 -eq "{02D4B3F1-FD88-11D1-960D-00805FC79235}") {
                $ProcName = "dllhost.exe (COM+ System Application Service)"
            } else {
                    $paramout = "dllhost.exe (AppID not in normal path)"
                    $regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\$cid2"
                    $paramout = (Get-ItemProperty -Path "Registry::$regPath" -ErrorAction SilentlyContinue).'(default)'  
                    $ProcName = "dllhost.exe ($paramout)"              
                
            }
        }


        #check if process still running
        if ((Get-Process -Id $ProcID -ErrorAction SilentlyContinue) -eq $null ) {
            $running = $false
        } else {
            $running = $true
        }



        $out += New-Object -TypeName psobject -Property @{ Index=$c; Date=$eventDate; Time=$eventTime; PID=$ProcID; Process=$ProcName; Cmd=$cmd; Running=$running; Domain=$Domain; User=$Account; Parent=$PPID; ParentProcess=$PProcName}

    }
    $html = "
        <html>
        <head>
        <title>Event Process Tracking for $env:Computername generated on $(get-date)</title>
            <script type=`"text/javascript`" src=`"vis.js`"></script>
            <link href=`"vis-network.min.css`" rel=`"stylesheet`" type=`"text/css`" />
            <style type=`"text/css`">
                #processmap {
                    width: 1200px;
                    height: 600px;
                    border: 1px solid lightgray;
                }

                table {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
                th {border-width: 1px; padding: 5px; border-style: solid; border-color: black; background-color: #95D8FF;}
                td {border-width: 1px; padding: 5px; border-style: solid; border-color: black;}
            </style>
            </style>
        </head>
        <body>
        <div id=`"processmap`"></div><div><br></div></div><div><br></div>
        <script type=`"text/javascript`">



            var nodes = ["
            
            
    [array]$parents = $out.parent | sort -Unique 
    
    $ptable = @()

    foreach ($p in $parents) {
        foreach ($o in $out) {
            if ($p -ne $o.PID) { $ptable += New-Object -TypeName psobject -Property @{ PID=$o.Parent; Process=$o.ParentProcess}}
        }
        
    }

    foreach ($p in $out) { $ptable += New-Object -TypeName psobject -Property @{ PID=$p.PID; Process=$p.Process}}
    
    #$deadpprocess = $ptable | select PID, Process -Unique
      
    #foreach ($p in $deadpprocess)  { $html += "{id:$($p.PID),label:'$($p.PID):$($p.Process)'}," } 
    
    $nodes = $ptable | select PID, Process -Unique | Sort -Property PID
      
    $maxrec = $nodes.count

        
    for ($i=0; $i -lt $maxrec; $i++)  { 
        $html += "{id:$($nodes[$i].PID),label:'$($nodes[$i].PID):$($nodes[$i].Process)'}"
        
        if ($i -ne $($maxrec - 1)) { $html +="," } else { $html +="];`n`r" }
        
    }

    $html += "
            var edges = ["

    
    
    for ($i=0; $i -lt $out.count; $i++)  { 
        $html += "{from:$($out[$i].Parent),to:$($out[$i].PID),id:`"e$($i)`"}"
        
        if ($i -ne $($out.count - 1)) { $html +="," } else { $html +="];`n`r" }
        
    }
    
    
    $html += "
            var container = document.getElementById('processmap');
            var data = {
                nodes: nodes,
                edges: edges
            };
            var options = {
                layout: {
                    hierarchical: {
                        direction: `"UD`",
                        sortMethod: `"directed`"
                    }
                },
                nodes: {
                        shape: 'box',
                        margin: 10,
                        widthConstraint: {
                            maximum: 200
                        }
                },
                interaction: {dragNodes :true},
                physics: {
                    enabled: false
                },
                configure: {
                  filter: function (option, path) {
                      if (path.indexOf('hierarchical') !== -1) {
                          return true;
                      }
                      return false;
                  },
                  showButton:false
                }
            };
            var network = new vis.Network(container, data, options);

         </script>`n"

    $htmlfrag = $out | select Index, Date, Time, PID, Process, Running, Domain, User, Parent, ParentProcess, Cmd | ConvertTo-Html -Fragment

    $html += "`t`t$htmlfrag"

    $html += "</body>"

    $html

    #$nodes 


   }

#change file path where to save output.
#also be aware, Chrome doesn't seem to load the Chart locally, I have not dug into it more but it could be a trust setting
#as Internet Explorer loads the file, you just have to click Enable Active X content.

Get-psEventLog-visjs  | Out-File -FilePath "C:\Users\pure\Desktop\file.htm"