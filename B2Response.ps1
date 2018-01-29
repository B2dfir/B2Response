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

If (-Not($args[0])){
	Write-Host "Please include remote hostname or ip as argument. E.g. ./B2Response.ps1 ProdServer1"
	exit
}
clear
$Date = Get-Date -UFormat %Y%m%d.%H.%M
$RemoteHost = $args[0]
$Logs = "$date-$RemoteHost"
$VerbosePreference='Continue'
$execcount = 0
Write-Host @"
 +-+-+-+-+-+-+-+-+-+-+
 |B|2|R|e|s|p|o|n|s|e|
 +-+-+-+-+-+-+-+-+-+-+
"@

#Connect to remote host
Write-Host "Attempting to connect to $RemoteHost"
$s1 = New-PSsession -ComputerName $RemoteHost -SessionOption (New-PSSessionOption -NoMachineProfile) -ErrorAction Stop

#Create Logging Directory
New-Item -Path $Logs -ItemType directory >$null 2>&1
Write-Host "Logging to " ((Resolve-Path .\).Path).trim()\$Logs\
  
#Functinon to read and validate user input
Function Menu{
    $Command = Read-Host "[$RemoteHost]> "
    if ($Command -ne 'dir' -and $Command -ne 'ls' -and $Command -ne 'help' -and $Command -ne '-h' -and $Command -ne 'autorunsc' -and $Command -ne 'prefetch' -and $Command -ne 'rekal' -and $Command -ne "users" -and (-Not($Command.StartsWith('iehistory'))) -and (-Not($Command.StartsWith('chromehistory'))) -and (-Not($Command.StartsWith('firefoxhistory'))) -and $Command -ne "netstat" -and $Command -ne "dnscache" -and $Command -ne 'exit' -and (-Not($Command.StartsWith('cd'))) -and (-Not($Command.StartsWith('mkdir'))) -and (-Not($Command.StartsWith('exec'))) -and (-Not($Command.StartsWith('upload'))) -and (-Not($Command.StartsWith('download'))) -and $Command -ne 'quit'){
        Write-Host "Unknown command. Type 'help' or '-h' for command list"
        }
    return $Command
   }


#Help Menu
Function Help{
    $help = @"

    Available commands:
    
    Command    Alias    Description
    -------    -----    -----------
    help       -h       Help
    dir        ls       List current directory contents
    cd                  Change current directory
    mkdir               Create directory
    upload              Uploads a file to remote host. Must use absolute paths and must wrap in double quotes
                        Syntax: 
                        upload "C:\local\host\test.txt" "C:\remote\host\test.txt"
    download            Download a file from remote host. Must use absolute paths and must wrap in double quotes
                        Syntax: 
                        download "C:\remote\host\test.txt" "C:\local\host\test.txt"
    users               Lists subfolders of C:\Users
    exec                Execute remote powershell command
    netstat             Execute netstat -an
    dnscache            Display dnscache
    prefetch            Get creation and modification timestamps (first and last execution times) of 
                        prefetch files within C:\Windows\Prefetch
    chromehistory       Parse Chrome browser history. Must specify username. E.g. chromehistory bobw.
                        Due to imperfect regex constraints, only a unique list of domains is presented
    firefoxhistory      Parse Firefox browser history. Must specify username. E.g. chromehistory bobw
                        Due to imperfect regex constraints, only a unique list of domains is presented
    iehistory           Parses Internet Explorer History
                        Due to imperfect regex constraints, only a unique list of domains is presented
    autorunsc           Copy Binaries\Autorunsc.zip to C:\Windows\Temp on remote host, extract and run
                        autorunsc.exe -a * -user * -c
                        Saves results to Logs\autorunsc.csv
    rekal*^             Copy Binaries\rekal.zip to C:\Windows\Temp on remote host, extract, and run rekal.exe live
    exit       quit     Close PSSession and exit B2Response

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
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock
    }
    If ($Command.StartsWith("mkdir")){
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command)
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock | Tee-Object -file "$Logs\mkdir.txt" -Append
    }
    If ($Command.StartsWith("upload")){
        $charCount = ($Command.ToCharArray() | Where-Object {$_ -eq '"'} | Measure-Object).Count
        if($charCount -eq 4){
            Copy-Item –Path ($Command.split('"')[1]) -Destination ($Command.split('"')[3]) –ToSession $s1
			Write-Output $Command | Tee-Object -file "$Logs\upload.txt" -Append
		}
        else{
            Write-Host 'Error: must wrap absolute paths in double quotes. E.g. upload "C:\test.txt" "C:\uploads\text.txt"'
        }
    }
    If ($Command.StartsWith("download")){
        $charCount = ($Command.ToCharArray() | Where-Object {$_ -eq '"'} | Measure-Object).Count
        if($charCount -eq 4){
            Copy-Item –Path ($Command.split('"')[1]) -Destination ($Command.split('"')[3]) –FromSession $s1
			Write-Output $Command | Tee-Object -file "$Logs\download.txt" -Append
            }
        else{
            Write-Host 'Error: must wrap absolute paths in double quotes. E.g. download "C:\test.txt" "C:\downloads\text.txt"'
            }
    }
    If ($Command -eq "users"){
        Invoke-Command -Session $s1 -ScriptBlock{Get-ChildItem -Path C:\Users -Directory -Force -ErrorAction SilentlyContinue | Select-Object Name} | ft -AutoSize | Tee-Object -file "$Logs\users.txt" -Append
    }
    If ($Command.StartsWith("exec")){
        $execcount += 1
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command.substring(5))
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock | Tee-Object -file $Logs\exec$execcount.txt
    }
    If ($Command -eq "netstat") {
        Invoke-Command -Session $s1 -ScriptBlock {netstat -an} | Tee-Object -file $Logs\netstat.txt
    }
    If ($Command -eq "dnscache") {
        Invoke-Command -Session $s1 -ScriptBlock {ipconfig /displaydns | select-string 'Record Name' | foreach-object { $_.ToString().Split(' ')[-1]   } | Sort} | Tee-Object -file "$Logs\dnscache.txt" -Append
    }
    If ($Command -eq "prefetch"){
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("Get-ChildItem C:\Windows\Prefetch -recurse -include @('*.pf')|Select-Object Name, CreationTime, LastWriteTime")
        Invoke-Command -Session $s1 -ScriptBlock $ScriptBlock | sort LastWriteTime -Descending | ft -autosize | Tee-Object -file "$Logs\prefetch.txt"
    }
    If ($Command.StartsWith("chromehistory")){
        If($Command.length -lt 15){
            Write-Host "Error: Please specify username (as it appears in C:\Users). E.g. chromehistory bobw"
        }
        If($Command.length -gt 15){
            $UserName = $Command.substring(14)
            Invoke-Command -Session $s1 -ScriptBlock {param($UserName)$Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
                if (-not (Test-Path -Path $Path)) {
                    Write-Host "[!] Could not find Chrome History for username: $UserName"
                }
                Write-Host "Note: Due to regex restraints, only a unique list of domains is presented"
                $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
                $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
                $Value | ForEach-Object {
                    $Key = $_
                    if ($Key -match $Search){
                New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'History'
                    Data = $_
                        }
                    }
                }
                } -ArgumentList $UserName| ft -AutoSize | Tee-Object -file "$Logs\chromehistory-$UserName.txt" -Append
            }
    }
    If ($Command.StartsWith("firefoxhistory")){
        If($Command.length -lt 15){
            Write-Host "Error: Please specify username (as it appears in C:\Users). E.g. firefoxhistory bobw"
        }
        If($Command.length -gt 15){
            $UserName = $Command.substring(15)
            Invoke-Command -Session $s1 -ScriptBlock {param($UserName)$Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
            if (-not (Test-Path -Path $Path)) {
                Write-Host "[!] Could not find FireFox History for username: $UserName"
            }
            else {
                Write-Host "Note: Due to regex restraints, only a unique list of domains is presented"
                $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
                $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
                $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
                $Value.Value |ForEach-Object {
                    if ($_ -match $Search) {
                        ForEach-Object {
                        New-Object -TypeName PSObject -Property @{
                            User = $UserName
                            Browser = 'Firefox'
                            DataType = 'History'
                            Data = $_
                            }    
                        }
                    }
                }
            }
            } -ArgumentList $UserName| ft -AutoSize | Tee-Object -file "$Logs\firefoxhistory-$UserName.txt" -Append
			}
        }
        If ($Command.StartsWith("iehistory")){
        $UserName=""
        Invoke-Command -Session $s1 -ScriptBlock {$Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

        ForEach($Path in $Paths) {

            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

            $Path = $Path | Select-Object -ExpandProperty PSPath

            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
            if (-not (Test-Path -Path $UserPath)) {
                Write-Verbose "[!] Could not find IE History for SID: $Path"
            }
            else {
                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Key = $_
                    $Key.GetValueNames() | ForEach-Object {
                        $Value = $Key.GetValue($_)
                        if ($Value -match $Search) {
                            New-Object -TypeName PSObject -Property @{
                                User = $UserName
                                Browser = 'IE'
                                DataType = 'History'
                                Data = $Value
                            }
                        }
                    }
                }
            }
        }
        Remove-PSDrive -Name "HKU"
        } -ArgumentList $UserName| ft -AutoSize| Tee-Object -file "$Logs\ieromehistory.txt" -Append
    }
    If ($Command -eq "autorunsc"){
        If (-Not(Test-Path \\$RemoteHost\C$\Windows\Temp\Autorunsc.zip)){
            Copy-Item –Path Binaries\Autorunsc.zip -Destination C:\Windows\Temp\Autorunsc.zip –ToSession $s1
        }
        If (-Not(Test-Path \\$RemoteHost\C$\Windows\Temp\Autorunsc\autorunsc.exe) -and (Test-Path \\$RemoteHost\C$\Windows\Temp\Autorunsc.zip)){
            Write-Host "Extracting Autorunsc.zip..."
            Invoke-Command -Session $s1 -ScriptBlock {Add-Type -assembly "system.io.compression.filesystem"}
            Invoke-Command -Session $s1 -ScriptBlock {[io.compression.zipfile]::ExtractToDirectory("C:\Windows\Temp\Autorunsc.zip", "C:\Windows\Temp")}
        }
        If (Test-Path \\$RemoteHost\C$\Windows\Temp\Autorunsc\autorunsc.exe) {
            Invoke-Command -Session $s1 -ScriptBlock {C:\Windows\Temp\Autorunsc\autorunsc.exe -a * -user * -c -accepteula;} | Tee-Object -file "$Logs\autoruns.csv" -Append
        }
    }
    If ($Command -eq "rekal"){
        If (-Not(Test-Path \\$RemoteHost\C$\Windows\Temp\rekal.zip)){
            Copy-Item –Path Binaries\rekal.zip -Destination C:\Windows\Temp\rekal.zip –ToSession $s1
        }
        If (-Not(Test-Path \\$RemoteHost\C$\Windows\Temp\Rekall) -and (Test-Path \\$RemoteHost\C$\Windows\Temp\rekal.zip)){
            Write-Host "Extracting rekal.zip..."
            Invoke-Command -Session $s1 -ScriptBlock {Add-Type -assembly "system.io.compression.filesystem"}
            Invoke-Command -Session $s1 -ScriptBlock {[io.compression.zipfile]::ExtractToDirectory("C:\Windows\Temp\rekal.zip", "C:\Windows\Temp")}
        }
		If (-Not(Test-Path .\Binaries\PsExec.exe)){
			Write-Host "Missing binary ./Binaries/PsExec.exe"
		}
        If ((Test-Path \\$RemoteHost\C$\Windows\Temp\Rekall\rekal.exe) -and (Test-Path .\Binaries\PsExec.exe)) {
            .\Binaries\PsExec.exe -accepteula \\$RemoteHost -s C:\Windows\Temp\Rekall\rekal.exe live
        }
    }
    If ($Command -eq "exit" -or $Command -eq "quit"){
		$QuitDate = Get-Date -UFormat %Y%m%d-%H:%M
		echo "Quit at $QuitDate (yyyymmdd-hh:mm)" > "$Logs\quit.txt"
        Remove-PSSession -Session $s1
        exit
        }
    }
