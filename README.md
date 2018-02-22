# B2Response (beta)
Logged PS Remote Command Wrapper for simplified Blue Team Forensics/IR.

Available commands:
-----------------------------------------------------------------------------------------------------------------------------

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
    lastactivityview^   lav       Copies Binaries\LastActivityView.exe to remote host and retrieves csv output file
    rekal*^                      Copy Binaries\rekal.zip to C:\Windows\Temp\B2R on remote host, extract, and run rekal.exe live
    exit               quit     Close PSSession and exit B2Response    
    
    *Not logged due to technical limitations
    ^Requires .\Binaries\PsExec.exe 

-----------------------------------------------------------------------------------------------------------------------------

## Usage
B2Response.ps1 -ComputerName remotehost

## Logging
B2Response will automatically create a time/hostname stamped logging subdirectory where executed, and will log the output from all commands executed, except Rekal.

## Cleanup
Simply enter the command 'cleanup' in the B2Response shell to delete C:\Windows\Temp\B2R recursively on the remote host.

## Dependencies
### Rekal:
1) Download and install rekal on your PC  
http://www.rekall-forensic.com/
2) Zip the install directory into rekal.zip
3) Place into the 'Binaries' folder

### Other Binaries:
1) Download exe  
BrowsingHistoryView: https://www.nirsoft.net/utils/browsing_history_view.html  
Autorunsc: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns  
LastAvtivityView: https://www.nirsoft.net/utils/computer_activity_view.html  
SigCheck: https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck  
2) Select the binary you wish to use (64 bit or 32 bit) and name it   
'browsinghistoryview.exe'  
'autorunsc.exe'  
'lastactivityview.exe'  
'sigcheck.exe'  
3) Place in the 'Binaries' folder

### Future feature additions:
Memory dump  
Packet capture  
Utilization of a network share for binary execution and file write (without breaking powershell 2nd hop rule)  
Additional parsers  
