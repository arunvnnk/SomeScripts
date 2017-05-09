#something that i wrote to detect child processes spawned by MSWORD (in an attempt to start profiling macro based malware) and learn some Powershell 
#this can be expanded to monitor all MS office products. In order to run this script, Open a new PS session window and do
# $query= "Select * from win32_ProcessStartTrace where processname='winword.exe'"
# Register-CiMIndicationEvent -Query $query -SourceIdentifier winword
#Only works for macro execution at open document; threat actor can do macro execution at close or delay execution to miss the anyalysis.
# To do - (monitor more processes,program for more conditions (like doc close, anti-sandbox techniques etc,some bug fixing)
#Please note, this is my first Powershell program ;)
function Start-Traversal{
param( 
 $arr
)
[string]$cast = $arr
Write-Host "in start-traversal"
Detail-ChildProcess($cast)
 
}	 
function Detail-ChildProcess{
param($ID)
Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" |  Select-Object -Property ProcessName,ProcessID,CommandLine 
$childprocesses=Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" |  Select-Object -Property ProcessName,ProcessID,CommandLine | foreach {$_.ProcessID}
foreach ($element in $childprocesses){Detail-ChildProcess $element}
}



$flag=1
while(1){
try { 
     
	 $test=(Get-Event -SourceIdentifier winword -ErrorAction Stop).SourceEventArgs.newevent | Select-Object $_ | foreach {$_.ProcessID} 
	 ($test).gettype()
  	 Start-Traversal($test)
	 $flag=1
	 Get-Event | Remove-Event
    }
catch
    { 
	  if ($flag -eq 1) 
      {
	   Write-Host "Waiting for events"
	   $flag=0
	  }
	  
    }
	  
}
