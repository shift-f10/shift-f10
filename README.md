Tracking down processes can sometimes take a long time and eventually, you will reach a dead end and you need to dig in the event-log to find processes with event id 4688.  Get-psEventLog.ps1 helps automate the process by parsing the relevant information.  It also converts the process IDs from hex to decimal to easily correlate with most utilities such as tasklist, etc.  It also checks to see if the process is currently running and check the AppID in the commandline (in the case of dllhost.exe) and bumps it against the registry to find the application name.

This script outputs to an html file to easily view the data.  In addition, mapping the processes using Google Chart.  

Must run the files with admin privs since security log requires admin.

Issues:
- Must be online to view the Chart as Google's license does not allow use of their API offline
- Must use IE to view file and allow content, Chrome for some reason has some settings to trust local files, I still need to look into that
