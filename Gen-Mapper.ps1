Function Gen-Mapper {
    


    Write-Host "1. Open your modern browser and navigate to http://jsfiddle.net" -ForegroundColor Gray
    Write-Host "`n"
    Write-Host "2. Copy the code below and paste into the HTML window." -ForegroundColor Gray
    Write-Host `<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script> 
    Write-Host `<div id="chart_div"></div> 
    Write-Host "`n" 
    Write-Host "3. Copy the code below and pase into the Javascript window." -ForegroundColor Gray
    Write-Host "`n"
    Write-Host "google.charts.load('current', {packages:[`"orgchart`"]});"
    Write-Host "google.charts.setOnLoadCallback(drawChart);"
    Write-Host "function drawChart() {"
    Write-Host "var data = new google.visualization.DataTable();"
    Write-Host "data.addColumn('string', 'PID');"
    Write-Host "data.addColumn('string', 'PPID');"
    Write-Host "data.addColumn('string', 'Information');"
    Write-Host "data.addRows(["
    
    # Change or remove the MaxEvents value to the number of items you want to see
    # or change the FilterXPath to a more defined filter
    $logs = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" -MaxEvents 100
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

        $PName = [regex]::Escape($ProcName) + ", " + [regex]::Escape($Account)

        Write-Host "['$ProcID', '$PPID', '$PName'],"

    } 
    Write-Host "['EventLog Mapper','','Charting Process 4688 history from eventlog.']]);"
    Write-Host "var chart = new google.visualization.OrgChart(document.getElementById('chart_div'));"
    Write-Host "chart.draw(data, {allowHtml:true});}"
    Write-Host "`n"
    Write-Host "4. Click the Run button to generate the map!" -ForegroundColor Gray
     
}    

Gen-Mapper 




