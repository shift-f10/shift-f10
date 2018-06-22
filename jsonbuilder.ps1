
    
    
    # Change or remove the MaxEvents value to the number of items you want to see
    # or change the FilterXPath to a more defined filter
    $logs = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" 
    
    # Initialize the array to store output
    $out = @()

    # Loop through the matching records, parse the data and store it in the array
    foreach ($entries in $logs) {

        #return PID
        $getpid = $entries.message -split "\r\n" | Select-String -SimpleMatch "New Process ID:"
        [array]$hexPID = $getpid -split ":"
        $ProcID = [System.Convert]::ToInt64($hexPID[1].trim(),16)

        #return Process Name
        $getproc = $entries.message -split "\r\n" | Select-String -SimpleMatch "New Process Name:"
        [array]$arrProc = $getproc -split "\t"
        $ProcName = $arrProc[2]

        #return Parent PID
        $getppid = $entries.message -split "\r\n" | Select-String -SimpleMatch "Creator Process ID:"
        [array]$hexPPID = $getppid -split ":"
        $PPID = [System.Convert]::ToInt64($hexPPID[1].trim(),16)

        #return Parent Process Name
        $getpproc = $entries.message -split "\r\n" | Select-String -SimpleMatch "Creator Process Name:"
        [array]$arrPProc = $getpproc -split "\t"
        $PProcName = $arrPProc[2]

        #return Account Name
        $getAcctinfo = $entries.message -split "\r\n" | Select-String -SimpleMatch "Account Name:"
        [array]$arrAcct = $getAcctinfo -split ":"
        $Account = $arrAcct[1].trim()

        #return Domain
        $getDomain = $entries.message -split "\r\n" | Select-String -SimpleMatch "Account Domain:"
        [array]$arrDomain = $getDomain -split ":"
        $Domain = $arrDomain[1].trim()


        $out += New-Object -TypeName psobject -Property @{ Timestamp = $entries.TimeCreated; PID=$ProcID; Process=$ProcName; Domain=$Domain; User=$Account; Parent=$PPID; ParentProcess=$PProcName}

    }
    
    ConvertTo-Json -InputObject $out | Out-File C:\Users\Public\out.json

    



