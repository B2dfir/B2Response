# B2Response (beta)
Logged PS Remote Command Wrapper for simplified Blue Team Forensics/IR

-----------------------------------------------------------------------------------------------------------------------------
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
    dnscache            Execute dnscache
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
    rekal*               Copy Binaries\rekal.zip to C:\Windows\Temp on remote host, extract, and run rekal.exe live
    exit       quit     Close PSSession and exit B2Response

*Not logged due to technical limitations

-----------------------------------------------------------------------------------------------------------------------------

Usage:
B2Response.ps1 remotehost

In order to use rekal:
1) Download and install rekal on your PC
2) Zip the install directory into rekal.zip
3) Place into the 'Binaries' folder

In order to use autorunsc (which is saved in a .csv log):
1) Download autorunsc
2) Select the binary you wish to use (64 bit or 32 bit) and name it 'autorunsc.exe'
3) Place it in a folder called 'Autorunsc'
4) Zip the folder 'Autorunsc' containing 'autorunsc.exe'
5) Place Autorunsc.zip into the 'Binaries' folder
