Tracking down processes can sometimes take a long time and eventually, you will reach a dead end and you need to dig in the event-log to find processes with event id 4688.  Get-psEventLog.ps1 helps automate the process.  The process IDs on the event log are in Hex and this helps convert them to a more user friendly decimal to easily correlate with most utilities.

Sometimes it is easier to visualize how these processes were launched, so I decided to utilize Google Chart to generate a visual representation of the events.  That's where Gen-Mapper.ps1 comes in.  Unfortunately I am very novice so you're going to have to cut and paste it to your fav browser in jfiddle.net.

Must run the files with admin privs since security log requires admin.
