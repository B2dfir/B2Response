  <#
.SYNOPSIS
  Remote PowerShell command wrapper which simplifies DFIR triage tasks and logs most command output on a single host.
.DESCRIPTION
  Remote PowerShell command wrapper which simplifies DFIR triage tasks and logs most command output on a single host.
.PARAMETER <Parameter_Name>
    Requires the remote host to connect to. E.g. B2Response.ps1 PubServer1
.OUTPUTS
  Logs are stored in a date/time stamped folder within the executed directory
.NOTES
  Version:        0.1
  Author:         Barnaby Skeggs
  Creation Date:  28 Jan 2018
  Purpose/Change: Initial script development
  
.EXAMPLE
  B2Response PubServer1
#>

Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$computerName
)

#Clear shell and set initialization variables
clear
$Date = Get-Date -UFormat %Y%m%d.%H.%M
$Logs = "$date-$computerName"
#$VerbosePreference='Continue'
$execcount = 0

#Write Logo
Write-Host @"
 +-+-+-+-+-+-+-+-+-+-+
 |B|2|R|e|s|p|o|n|s|e|
 +-+-+-+-+-+-+-+-+-+-+
"@

#Initiate Session with remote host
Write-Host "Attempting to connect to $computerName"
try{
    $s1 = New-PSsession -ComputerName $computerName -SessionOption (New-PSSessionOption -NoMachineProfile) -ErrorAction Stop
}
catch{
    Write-Host "Error estabilshing session with remote host"
    $_.Exception.Message
}

#Create temporary folder on remote host for binary and file transfer
try{
    If (-NOT(Invoke-Command -Session $s1 -ScriptBlock {Test-Path \\$computerName\C$\Windows\Temp\B2R})){
        Write-Host "Creating temporary directory \\$computerName\C$\Windows\Temp\B2R"
        New-Item -Path "\\$computerName\C$\Windows\Temp\B2R" -ItemType directory >$null 2>&1
    }
    Else{
        Write-Host "Temporary directory already exists: \\$computerName\C$\Windows\Temp\B2R"
    }
}
catch{
    Write-Host "Error creating temporary directory on remote host"
    $_.Exception.Message
}

#Create Logging Directory
New-Item -Path $Logs -ItemType directory >$null 2>&1
Write-Host "Logging to " ((Resolve-Path .\).Path).trim()\$Logs\
  
#Functinon to read and validate user input
Function Menu{
    $Command = Read-Host "[$computerName]> "
    if ($Command -ne 'dir' -and $Command -ne 'ls' -and $Command -ne 'help' -and $Command -ne '-h' -and $Command -ne 'pslist' -and $Command -ne 'cleanup' -and $Command -ne 'autorunsc' -and $Command -ne "browsinghistoryview" -and $Command -ne "bhv" -and $Command -ne "lav" -and $Command -ne "lastactivityview" -and $Command -ne 'prefetch' -and (-Not($Command.StartsWith('sigcheck'))) -and $Command -ne 'rekal' -and $Command -ne "users" -and $Command -ne "netstat" -and $Command -ne "dnscache" -and $Command -ne 'exit' -and (-Not($Command.StartsWith('cd'))) -and (-Not($Command.StartsWith('mkdir'))) -and (-Not($Command.StartsWith('exec'))) -and (-Not($Command.StartsWith('upload'))) -and (-Not($Command.StartsWith('download'))) -and $Command -ne 'quit'){
        Write-Host "Unknown command. Type 'help' or '-h' for command list"
        }
    return $Command
   }

#Help Menu
Function Help{
    $help = @"

    Available commands:
    
    Command             Alias    Description
    -------             -----    -----------
    help                -h       Help
    dir                 ls       List current directory contents
    cd                           Change current directory
    mkdir                        Create directory
    pslist              ps       List running processes
    upload                       Uploads a file to remote host. Must use absolute paths and must wrap in double quotes
                                 Syntax: 
                                 upload "C:\local\host\test.txt" "C:\remote\host\test.txt"
    download                     Download a file from remote host. Must use absolute paths and must wrap in double quotes
                                 Syntax: 
                                 download "C:\remote\host\test.txt" "C:\local\host\test.txt"
    users                        Lists subfolders of C:\Users
    exec                         Execute remote powershell command
    netstat                      Execute netstat -an
    dnscache                     Execute dnscache
    browsinghistoryview bhv^     Copies Binaries\BrowsingHistoryView.exe to remote host and retrieves csv output file
    prefetch                     Get creation and modification timestamps (first and last execution times) of 
                                 prefetch files within C:\Windows\Prefetch
    autorunsc                    Copy Binaries\Autorunsc.zip to C:\Windows\Temp\B2R on remote host, extract and run
                                 autorunsc.exe -a * -user * -c
                                 Saves results to Logs\autorunsc.csv
    sigcheck                     Checks for packed binary executables using sigcheck.exe. Outputs files with entropy 7+
                                 Copies Binaries\sigcheck.exe to C:\Windows\Temp\B2R on remote host and runs.
                                 Default execution runs against C:\Windows\System32 with entropy 7+
                                 Custom syntax: sigcheck C:\Path Entropy
                                 E.g. sigcheck C:\Windows\Temp\B2R 7
    lastactivityview^  lav       Copies Binaries\LastActivityView.exe to remote host and retrieves csv output file
    rekal*^                      Copy Binaries\rekal.zip to C:\Windows\Temp\B2R on remote host, extract, and run rekal.exe live
    cleanup                      Deletes C:\Windows\Temp\B2R on remote host
    exit                quit     Close PSSession and exit B2Response

*Not logged due to technical limitations
^Requires .\Binaries\PsExec.exe

"@
    Write-Host $help
    }

#Main Loop. Runs until 'exit' is entered as a command.
While (1 -eq 1) {
    
    $Command = Menu

    If ($Command -eq "help" -or $Command -eq "-h"){
        Help
    }
    If ($Command -eq "dir" -or $Command -eq "ls"){
        Invoke-Command -Session $s1 -ScriptBlock {Get-ChildItem} | Tee-Object -file "$Logs\dir.txt" -Append
    }
    If ($Command.StartsWith("cd")){
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command)                
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock | Tee-Object -file "$Logs\cd.txt" -Append
    }
    If ($Command.StartsWith("mkdir")){
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command)
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock | Tee-Object -file "$Logs\mkdir.txt" -Append
    }
    If ($Command -eq "pslist" -or $Command -eq "ps"){
        Invoke-Command -Session $s1 -ScriptBlock {Get-Process} | Tee-Object -file "$Logs\pslist.txt" -Append
    }
    If ($Command.StartsWith("upload")){
        $charCount = ($Command.ToCharArray() | Where-Object {$_ -eq '"'} | Measure-Object).Count
        if($charCount -eq 4){
            try{
                Copy-Item -Path ($Command.split('"')[1]) -Destination ($Command.split('"')[3]) -ToSession $s1
			    Write-Host "File upload succeeded $Command" | Tee-Object -file "$Logs\upload.txt" -Append
            }
            catch{
                Write-Host "File upload failed: $Command" | Tee-Object -file "$Logs\upload.txt" -Append
            }
		}
        else{
            Write-Host 'Error: must wrap absolute paths in double quotes. E.g. upload "C:\test.txt" "C:\uploads\text.txt"'
        }
    }
    If ($Command.StartsWith("download")){
        $charCount = ($Command.ToCharArray() | Where-Object {$_ -eq '"'} | Measure-Object).Count
        if($charCount -eq 4){
            try{
                Copy-Item -Path ($Command.split('"')[1]) -Destination ($Command.split('"')[3]) -FromSession $s1
			    Write-Host "File download succeeded: $Command" | Tee-Object -file "$Logs\download.txt" -Append
            }
            catch{
                Write-Host "File download failed: $Command" | Tee-Object -file "$Logs\download.txt" -Append
            }
        }    
        else{
            Write-Host 'Error: must wrap absolute paths in double quotes. E.g. download "C:\test.txt" "C:\downloads\text.txt"'
        }
    }
    If ($Command -eq "users"){
        Invoke-Command -Session $s1 -ScriptBlock{Get-ChildItem -Path C:\Users -Directory -Force -ErrorAction SilentlyContinue | Select-Object Name} | ft -AutoSize | Tee-Object -file "$Logs\users.txt" -Append
    }
    If ($Command.StartsWith("exec")){
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command.substring(5))
        $execcount += 1
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock | Tee-Object -file $Logs\exec$execcount.txt
    }
    If ($Command -eq "netstat") {
        Invoke-Command -Session $s1 -ScriptBlock {netstat -an} | Tee-Object -file $Logs\netstat.txt
    }
    If ($Command -eq "dnscache") {
        Invoke-Command -Session $s1 -ScriptBlock {ipconfig /displaydns | select-string 'Record Name' | foreach-object { $_.ToString().Split(' ')[-1]   } | Sort} | Tee-Object -file "$Logs\dnscache.txt" -Append
    }
    If ($Command -eq "prefetch"){
        Invoke-Command -Session $s1 -ScriptBlock {Get-ChildItem C:\Windows\Prefetch -recurse -include @('*.pf')|Select-Object Name, CreationTime, LastWriteTime} | sort LastWriteTime -Descending | ft -autosize | Tee-Object -file "$Logs\prefetch.txt"
    }
    If ($Command -eq "autorunsc"){
        If (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\autorunsc.exe})){
            try{
                Write-Host "Attempting to copy binary to \\$computerName\C$\Windows\Temp\B2R\"
                Copy-Item -Path .\Binaries\autorunsc.exe -Destination C:\Windows\Temp\B2R\autorunsc.exe -ToSession $s1 -ErrorAction Stop
            }
            catch{
                $_.Exception.Message
            }
        }
        If (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\autorunsc.exe}){
            Write-Host "Copy successful. Executing..."
            try{
                Invoke-Command -Session $s1 -ScriptBlock {C:\Windows\Temp\B2R\autorunsc.exe -a * -user * -c -accepteula;} | Tee-Object -file "$Logs\autoruns.csv" -Append
            }
            catch{
                $_.Exception.Message
            }
        }
    }
    If ($Command.StartsWith("sigcheck")){
        $SigEntropy = 7
        $SigPath = "C:\Windows\System32\*"
        If ($Command -ne "sigcheck"){
            $SigEntropy = $Command.split(" ")[-1]
            $SigPath = $Command.substring(9).replace(" $SigEntropy","")
            If ($SigPath.Substring($SigPath.length-1) -ne "\"){
                $SigPath = $SigPath + "\*"
            }
            ElseIf ($SigPath.Substring($SigPath.length-1) -eq "\"){
                $SigPath = $SigPath + "*"
            }
        }
        If (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\sigcheck.exe})){
            try{
                Write-Host "Attempting to copy binary to \\$computerName\C$\Windows\Temp\B2R\"
                Copy-Item -Path Binaries\sigcheck.exe -Destination C:\Windows\Temp\B2R\sigcheck.exe -ToSession $s1 -ErrorAction Stop
            }
            catch{
                $_.Exception.Message
            }
        }
        If (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\sigcheck.exe}) {
            Write-Host "Copy successful. Executing... No output will be shown until an entropy match is found, so output may stay blank for a time"
            try{
                Invoke-Command -Session $s1 -ScriptBlock {param($SigPath,$SigEntropy) ForEach ($file in Get-ChildItem -Path $SigPath -Include *.cpl,*.exe,*.dll,*.ocx,*.sys,*.scr){$a=C:\Windows\Temp\B2R\sigcheck.exe -accepteula -a -e -c $file.Fullname | select -Skip 4 | ConvertFrom-Csv;if($a.Entropy -gt $SigEntropy){$a | select path,verified,publisher,entropy}}} -ArgumentList ($SigPath, $SigEntropy) | Tee-Object -file "$Logs\sigcheck.txt" -Append 
            }
            catch{
                $_.Exception.Message
            }
        }
    }
    If ($Command -eq "lastactivityview" -or $Command -eq "lav"){
        If (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\LastActivityView.exe})){
            try{
                Write-Host "Attempting to copy binary to \\$computerName\C$\Windows\Temp\B2R\"
                Copy-Item -Path Binaries\LastActivityView.exe -Destination C:\Windows\Temp\B2R\LastActivityView.exe -ToSession $s1 -ErrorAction Stop
            }
            catch{
                $_.Exception.Message
            }
        }
		If (-Not(Test-Path .\Binaries\PsExec.exe)){
			Write-Host "Missing binary ./Binaries/PsExec.exe"
		}
        If ((Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\LastActivityView.exe}) -and (Test-Path .\Binaries\PsExec.exe)) {
            Write-Host "Copy Successful. Executing..."
            .\Binaries\PsExec.exe -accepteula \\$computerName C:\Windows\Temp\B2R\LastActivityView.exe /scomma C:\Windows\Temp\B2R\lastactivityview.csv
        }
        If (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\lastactivityview.csv}){
            Copy-Item -Path C:\Windows\Temp\B2R\lastactivityview.csv -Destination $Logs\lastactivityview.csv -FromSession $s1
        }
        If (Test-Path $Logs\lastactivityview.csv){
            Write-Host "Output saved to $Logs\lastactivityview.csv"
        }
        Else{
            Write-Host "Error retrieving results. Check \\$computerName\C$\Windows\Temp\B2R\lastactivityview.csv to see if results were captured on remote host"
        }
    }
    If ($Command -eq "browsinghistoryview" -or $Command -eq "bhv"){
        If (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\BrowsingHistoryView.exe})){
            try{
                Write-Host "Attempting to copy binary to \\$computerName\C$\Windows\Temp\B2R\"
                Copy-Item -Path .\Binaries\BrowsingHistoryView.exe -Destination C:\Windows\Temp\B2R\BrowsingHistoryView.exe -ToSession $s1 -ErrorAction Stop
            }
            catch{
                $_.Exception.Message
            }
        }
		If (-Not(Test-Path .\Binaries\PsExec.exe)){
			Write-Host "Missing binary ./Binaries/PsExec.exe"
		}
        If ((Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\BrowsingHistoryView.exe}) -and (Test-Path .\Binaries\PsExec.exe)) {
            Write-Host "Copy Successful. Executing..."
            .\Binaries\PsExec.exe -accepteula \\$computerName C:\Windows\Temp\B2R\BrowsingHistoryView.exe /HistorySource 1 /scomma C:\Windows\Temp\B2R\browsinghistoryview.csv
        }
        If (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\browsinghistoryview.csv}){
            Copy-Item -Path C:\Windows\Temp\B2R\browsinghistoryview.csv -Destination $Logs\browsinghistoryview.csv -FromSession $s1
        }
        If (Test-Path $Logs\browsinghistoryview.csv){
            Write-Host "Output saved to $Logs\browsinghistoryview.csv"
        }
        Else{
            Write-Host "Error retrieving results. Check \\$computerName\C$\Windows\Temp\B2R\browsinghistoryview.csv to see if results were captured on remote host"
        }
    }
    If ($Command -eq "rekal"){
        If (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\rekal.zip})){
            try{
                Write-Host "Attempting to copy zip to \\$computerName\C$\Windows\Temp\B2R\"
                Copy-Item -Path Binaries\rekal.zip -Destination C:\Windows\Temp\B2R\rekal.zip -ToSession $s1  | Out-Null
            }
            catch{
                $_.Exception.Message
            }
        }
        If (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\Rekall}) -and (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\rekal.zip})){
            Write-Host "Copy successful. Extracting rekal.zip..."
            Invoke-Command -Session $s1 -ScriptBlock {Add-Type -assembly "system.io.compression.filesystem"}
            Invoke-Command -Session $s1 -ScriptBlock {[io.compression.zipfile]::ExtractToDirectory("C:\Windows\Temp\B2R\rekal.zip", "C:\Windows\Temp\B2R")}
        }
		If (-Not(Test-Path .\Binaries\PsExec.exe)){
			Write-Host "Missing binary ./Binaries/PsExec.exe"
		}
        If ((Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\Rekall\rekal.exe}) -and (Test-Path .\Binaries\PsExec.exe)) {
            .\Binaries\PsExec.exe -accepteula \\$computerName -s C:\Windows\Temp\B2R\Rekall\rekal.exe live
        }
    }
    If (($Command -eq "cleanup") -and (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R\})){
        try{
            Invoke-Command -Session $s1 -ScriptBlock {Remove-Item -Path 'C:\Windows\Temp\B2R\' -recurse -force} 
        }
        catch{
            $_.Exception.Message
        }
        if (Invoke-Command -Session $s1 -ScriptBlock {Test-Path C:\Windows\Temp\B2R}){
            Write-Host "'\\$computerName\C$\Windows\Temp\B2R' deletion failed" | Tee-Object -file "$Logs\cleanup.txt" -Append
        }
        elseif (-Not(Invoke-Command -Session $s1 -ScriptBlock {Test-Path \\$computerName\C$\Windows\Temp\B2R})){
            Write-Host "'\\$computerName\C$\Windows\Temp\B2R' deleted successfully!" | Tee-Object -file "$Logs\cleanup.txt" -Append
        }
    }
    If ($Command -eq "exit" -or $Command -eq "quit"){
		$QuitDate = Get-Date -UFormat %Y%m%d-%H:%M
		echo "Quit at $QuitDate (yyyymmdd-hh:mm)" > "$Logs\quit.txt"
        Remove-PSSession -Session $s1
        exit
        }
    } 
 

