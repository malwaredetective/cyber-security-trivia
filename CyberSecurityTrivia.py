import random
# Cyber Security Trivia
# The questions, answers, and resources containing additional information are stored in a list of tuples, so that the question and the corresponding elements can easily be referenced programatically.

# AWS
aws = [("What is the unique ID prefix that AWS applies to an IAM user?\n\nA: AIDA\nB: AKIA\nC: AROA\nD: ASIA\n\nA, B, C, D?", "A", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids"),
("What is the unique ID prefix that AWS applies to an Access Key?\n\nA: AIDA\nB: AKIA\nC: AROA\nD: ASIA\n\nA, B, C, D?", "B", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids"),
("What is the unique ID prefix that AWS applies to an IAM role?\n\nA: AIDA\nB: AKIA\nC: AROA\nD: ASIA\n\nA, B, C, D?", "C", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids"),
("What is the unique ID prefix that AWS applies to a temporary AWS STS Access Key?\n\nA: AIDA\nB: AKIA\nC: AROA\nD: ASIA\n\nA, B, C, D?", "D", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids"),
("What AWS CLI command within the STS service is the equivilent to whoami?\n\nA: get-caller-identity\nB: get-session-token\nC: get-user\nD: list-users\n\nA, B, C, D?", "A", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sts/get-caller-identity.html"),
("What AWS CLI command within the IAM service will retrieve information about a specified IAM user?\n\nA: get-caller-identity\nB: get-session-token\nC: get-user\nD: list-users\n\nA, B, C, D?", "C", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/get-user.html"),
("What AWS CLI command within the IAM service will return information on all of the IAM users within an account?\n\nA: get-caller-identity\nB: get-session-token\nC: get-user\nD: list-users\n\nA, B, C, D?", "D", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/list-users.html"),
("What AWS CLI command within the IAM service will provide an IAM user with programmatic access to AWS?\n\nA: create-access-key\nB: create-login-profile\nC: create-user\nD: create-policy\n\nA, B, C, D?", "A", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html#cli-aws-iam"),
("What AWS CLI command within the IAM service will provide an IAM user with console access into AWS?\n\nA: create-access-key\nB: create-login-profile\nC: create-user\nD: create-policy\n\nA, B, C, D?", "B", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html#cli-aws-iam"),
("What AWS CLI command within the IAM service will create a new IAM user?\n\nA: create-access-key\nB: create-login-profile\nC: create-user\nD: create-policy\n\nA, B, C, D?", "C", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html#cli-aws-iam"),
("From a defenders perspective, what AWS CLI command within the IAM service would not be classified as a persistence mechanism?\n\nA: create-access-key\nB: create-login-profile\nC: create-user\nD: create-policy\n\nA, B, C, D?", "D", "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html#cli-aws-iam")]

# Common Ports Numbers and their Default Services
commonPorts = [("What is the default Port Number for FTP Data?", "20", "https://www.speedguide.net/port.php?port=20"),
("What is the default Port Number for FTP Control?", "21", "https://www.speedguide.net/port.php?port=21"),
("What is the default Port Number for SSH?", "22", "https://www.speedguide.net/port.php?port=22"),
("What is the default Port Number for Telnet?", "23", "https://www.speedguide.net/port.php?port=23"),
("What is the default Port Number for SMTP?", "25", "https://www.speedguide.net/port.php?port=25"),
("What is the default Port Number for DNS?", "53", "https://www.speedguide.net/port.php?port=53"),
("What is the default Port Number for the DHCP server?", "67", "https://www.speedguide.net/port.php?port=67"),
("What is the default Port Number for the DHCP client?", "68", "https://www.speedguide.net/port.php?port=68"),
("What is the default Port Number for TFTP?", "69", "https://www.speedguide.net/port.php?port=69"),
("What is the default Port Number for HTTP?", "80", "https://www.speedguide.net/port.php?port=80"),
("What is the default Port Number for Kerberos?", "88", "https://www.speedguide.net/port.php?port=88"),
("What is the default Port Number for POP3?", "110", "https://www.speedguide.net/port.php?port=110"),
("What is the default Port Number for NTP?", "123", "https://www.speedguide.net/port.php?port=123"),
("What is the default Port Number for IMAP?", "143", "https://www.speedguide.net/port.php?port=143"),
("What is the default Port Number for LDAP?", "389", "https://www.speedguide.net/port.php?port=389"),
("What is the default Port Number for HTTPS?", "443", "https://www.speedguide.net/port.php?port=443"),
("What is the default Port Number for the latest version of SMB?", "445", "https://www.speedguide.net/port.php?port=445"),
("What is the default Port Number for RDP?", "3389", "https://www.speedguide.net/port.php?port=3389")]

# Windows Forensics
forensics = [("What is the value of the ADS Zone.Identifier that indicates a file was downloaded from the Internet?\n\nA: 1\nB: 2\nC: 3\nD: 4\n\nA, B, C, D?","C", "https://windowsforensics.net/database/file-download/ads-zone-identifier.html"), 
("What Event ID in the Security.evtx log indicates that an account was successfully logged on?\n\nA: 4624\nB: 4625\nC: 4648\nD: 4720\n\nA, B, C, D?","A", "https://windowsforensics.net/database/account-usage/logon-types.html"), 
("What Event ID in the Security.evtx log indicates that an account failed to logon?\n\nA: 4624\nB: 4625\nC: 4648\nD: 4720\n\nA, B, C, D?","B", "https://windowsforensics.net/database/account-usage/success-failed-logons.html"),
("What is the Logon Type for a 4624 event when the user logs in via the console?\n\nA: 2\nB: 3\nC: 5\nD: 10\n\nA, B, C, D?","A", "https://windowsforensics.net/database/account-usage/logon-types.html"),
("What is the Logon Type for a 4624 event when the user logs in via RDP?\n\nA: 2\nB: 3\nC: 5\nD: 10\n\nA, B, C, D?","D", "https://windowsforensics.net/database/account-usage/logon-types.html"),
("In Windows 10, which forensic artifact associated with the Windows Registry keeps track of user searches within Windows Explorer?\n\nA: NTUSER.DAT\nB: SAM\nC: SYSTEM\nD: SOFTWARE\n\nA, B, C, D?","A", "https://windowsforensics.net/database/file-knowledge/search-wordwheelquery.html"),
("Which forensic artifact associated with the Windows Registry could be analyzed to determine the last time a local user changed their password?\n\nA: NTUSER.DAT\nB: SAM\nC: SYSTEM\nD: SOFTWARE\n\nA, B, C, D?","B", "https://windowsforensics.net/database/account-usage/last-password-change.html"),
("Which Event Log keeps track of changes related to Windows Services?\n\nA: Application\nB: Security\nC: Setup\nD: System\n\nA, B, C, D?","D", "https://windowsforensics.net/database/account-usage/services-events.html"),
("Which Event Log keeps track of authentication events?\n\nA: Application\nB: Security\nC: Setup\nD: System\n\nA, B, C, D?","B", "https://windowsforensics.net/database/account-usage/authentication-events.html"),
("What is the name of the database on the local file system that Chrome uses to store users browser history?\n\nA: Cookies\nB: History\nC: Trusted Vault\nD: Web Data\n\nA, B, C, D?","B","History", "https://windowsforensics.net/database/browser-usage/history.html"),
("What type of database does Firefox use to store users browser history?\n\nA: MongoDB\nB: MySQL\nC: PostgreSQL\nD: SQLite\n\nA, B, C, D?","D", "https://windowsforensics.net/database/file-download/downloads.html"),
("Within NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU, which subkey will keep track of the last 20 saved files, regardless of file extension?\n\nA: *\nB: exe\nC: pdf\nD: txt\n\nA, B, C, D?","A", "https://windowsforensics.net/database/file-download/open-save-mru.html"),
("When performing forensics on files within the Recycle Bin, which file contains meta-data about the file?\n\nA: $D\nB: $I\nC: $M\nD: $R\n\nA, B, C, D?", "B", "https://windowsforensics.net/database/file-knowledge/recycle-bin.html"),
("When performing forensics on files within the Recycle Bin, which file contains recovery data needed to restore the file?\n\nA: $D\nB: $I\nC: $M\nD: $R\n\nA, B, C, D?", "D", "https://windowsforensics.net/database/file-knowledge/recycle-bin.html"),
("True or False? Windows Prefetch is disabled by default on Windows Server Operating Systems?","True", "https://windowsforensics.net/database/program-execution/prefetch.html"),
("CMD.EXE-73D024B2.pf is a Windows forensic artifact that can be found in C:\Windows\________?\n\nA: appcompat\nB: Prefetch\nC: System32\nD: Temp\n\nA, B, C, D?", "B","Prefetch", "https://windowsforensics.net/database/program-execution/prefetch.html")]

# Linux
linux = [("What command will list the contents of the current directory when executed within a Linux terminal?\n\nA: cd\nB: dir\nC: ls\nD: pwd\n\nA, B, C, D?", "C", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command will print the current working directory when executed within a Linux terminal?\n\nA: cd\nB: dir\nC: ls\nD: pwd\n\nA, B, C, D?", "D", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to change directories when executed within a Linux terminal?\n\nA: cd\nB: dir\nC: ls\nD: pwd\n\nA, B, C, D?", "A", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to lookup how a command functions within a Linux terminal?\n\nA: Get-Help\nB: help\nC: man\nD: /?\n\nA, B, C, D?", "C", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What is the default package manager for most Debian-based Linux distributions?\n\nA: apt\nB: pacman\nC: pip\nD: yum\n\nA, B, C, D?", "A", "https://ubuntu.com/server/docs/package-management"),
("What is the default package manager for most Red Hat Linux distributions?\n\nA: apt\nB: pacman\nC: pip\nD: yum\n\nA, B, C, D?", "D", "https://www.redhat.com/sysadmin/how-manage-packages"),
("What command will display the contents of a file within a Linux terminal?\n\nA: cat\nB: grep\nC: strings\nD: wc\n\nA, B, C, D?", "A", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to print lines from a file that match a specific pattern?\n\nA: cat\nB: grep\nC: strings\nD: wc\n\nA, B, C, D?", "B", "https://www.tutorialspoint.com/unix_commands/grep.htm"),
("What command can be used to print out all of the ASCII strings within a file?\n\nA: cat\nB: grep\nC: strings\nD: wc\n\nA, B, C, D?", "C", "https://www.tutorialspoint.com/unix_commands/strings.htm"),
("What command can be used to count how many characters are in a file?\n\nA: cat\nB: grep\nC: strings\nD: wc\n\nA, B, C, D?", "D", "https://www.tutorialspoint.com/unix_commands/wc.htm"),
("What command will copy a file from one location to another when executed within a Linux terminal?\n\nA: cp\nB: mkdir\nC: mv\nD: rmdir\n\nA, B, C, D?", "A", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to create a new directory when executed within a Linux terminal?\n\nA: cp\nB: mkdir\nC: mv\nD: rmdir\n\nA, B, C, D?", "B", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to move a file from one directory to another when executed within a Linux terminal?\n\nA: cp\nB: mkdir\nC: mv\nD: rmdir\n\nA, B, C, D?", "C", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to delete a directory when executed within a Linux terminal?\n\nA: cp\nB: mkdir\nC: mv\nD: rmdir\n\nA, B, C, D?", "D", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What directory is commonly used to store system configuration files within a Linux OS?\n\nA: etc\nB: home\nC: tmp\nD: var\n\nA, B, C, D?", "A", "https://www.linux.com/training-tutorials/linux-filesystem-explained/"),
("What directory is commonly used to store users personal files within a Linux OS?\n\nA: etc\nB: home\nC: tmp\nD: var\n\nA, B, C, D?", "B", "https://www.linux.com/training-tutorials/linux-filesystem-explained/"),
("What directory is commonly used to store volatile data within a Linux OS?\n\nA: etc\nB: home\nC: tmp\nD: var\n\nA, B, C, D?", "C", "https://www.linux.com/training-tutorials/linux-filesystem-explained/"),
("What directory is commonly used to store log files within a Linux OS?\n\nA: etc\nB: home\nC: tmp\nD: var\n\nA, B, C, D?", "D", "https://www.linux.com/training-tutorials/linux-filesystem-explained/"),
("What command can be used to modify the permissions of a file when executed within a Linux terminal?\n\nA: chmod\nB: locate\nC: sudo\nD: which\n\nA, B, C, D?", "A", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be used to search for a file when executed within a Linux terminal?\n\nA: chmod\nB: locate\nC: sudo\nD: which\n\nA, B, C, D?", "B", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command can be prepended to another command to temporarily achieve administrative rights when executed within a Linux terminal?\n\nA: chmod\nB: locate\nC: sudo\nD: which\n\nA, B, C, D?", "C", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners"),
("What command will return the file path of a specified command when executed within a Linux terminal?\n\nA: chmod\nB: locate\nC: sudo\nD: which\n\nA, B, C, D?", "D", "https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners")]

# Magic Numbers
magic = [("What is the Magic Number for an executable file type that will run on a Linux OS?\n\nA: .ELF\nB: MZ\nC: %PDF\nD: PK\n\nA, B, C, D?","A", "https://en.wikipedia.org/wiki/List_of_file_signatures"),
("What is the Magic Number for a DOS executable file that will run on a Windows OS?\n\nA: .ELF\nB: MZ\nC: %PDF\nD: PK\n\nA, B, C, D?","B", "https://en.wikipedia.org/wiki/List_of_file_signatures"),
("What is the Magic Number for a file stored in the Portable Document Format?\n\nA: .ELF\nB: MZ\nC: %PDF\nD: PK\n\nA, B, C, D?","C", "https://en.wikipedia.org/wiki/List_of_file_signatures"),
("What is the Magic Number often used by compressed file formats?\n\nA: .ELF\nB: MZ\nC: %PDF\nD: PK\n\nA, B, C, D?","D", "https://en.wikipedia.org/wiki/List_of_file_signatures")]

# Malware
malware = [("What type of malware attempts to hold the victims data hostage until they pay?\n\nA: Keyloggers\nB: Botnet\nC: Ransomware\nD: Trojan\n\nA, B, C, D?","C", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"),
("What type of malware could be leveraged in a large Distributed Denial of Service attack?\n\nA: Keyloggers\nB: Botnet\nC: Ransomware\nD: Trojan\n\nA, B, C, D?","B", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"),
("What type of malware would most likely be used to intercept a vicims password as they log into their online back?\n\nA: Keyloggers\nB: Botnet\nC: Ransomware\nD: Trojan\n\nA, B, C, D?","A", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"),
("What type of malware is often disguised as legitimate software?\n\nA: Keyloggers\nB: Botnet\nC: Ransomware\nD: Trojan\n\nA, B, C, D?","D", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"), 
("What type of malware automatically renders advertisements in order to generate revenue for the malware author?\n\nA: Adware\nB: Dropper\nC: RAT\nD: Worm\n\nA, B, C, D?","A", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"),
("What type of malware is only stage one of a multi-staged attack chain?\n\nA: Adware\nB: Dropper\nC: RAT\nD: Worm\n\nA, B, C, D?","B", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"),
("What type of malware provides an attacker with Command and Control access into the victims machine?\n\nA: Adware\nB: Dropper\nC: RAT\nD: Worm\n\nA, B, C, D?","C", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/"),
("What type of malware has the ability to self-propagate to other systems on the network without user interaction?\n\nA: Adware\nB: Dropper\nC: RAT\nD: Worm\n\nA, B, C, D?","D", "https://www.crowdstrike.com/cybersecurity-101/malware/types-of-malware/")]

# Binary/Decimal/Hexadecimal
numbers = [("Convert the binary value of 0010 to decimal?", "2", "https://www.mathsisfun.com/binary-number-system.html"),
("Convert the hex value of 0x10 to decimal?", "16", "https://www.mathsisfun.com/hexadecimals.html"),
("Convert the binary value of 1111 to decimal?", "15", "https://www.mathsisfun.com/binary-number-system.html"),
("Convert the hex value of 0x0F to decimal.", "15", "https://www.mathsisfun.com/hexadecimals.html"),
("Convert the binary value of 1010 to decimal.", "10", "https://www.mathsisfun.com/binary-number-system.html")]

# The OSI Model and their corresponding Layers
osiModel = [("What is layer 1 of the OSI Model?","Physical", "https://en.wikipedia.org/wiki/OSI_model"),
#("What is layer 2 of the OSI Model: (____ ____)?","Data Link", "https://en.wikipedia.org/wiki/OSI_model"),
("What is layer 3 of the OSI Model?","Network", "https://en.wikipedia.org/wiki/OSI_model"),
("What is layer 4 of the OSI Model?","Transport", "https://en.wikipedia.org/wiki/OSI_model"),
("What is layer 5 of the OSI Model?","Session", "https://en.wikipedia.org/wiki/OSI_model"),
("What is layer 6 of the OSI Model?","Presentation", "https://en.wikipedia.org/wiki/OSI_model"),
("What is layer 7 of the OSI Model?","Application", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Physical layer?","1", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Data Link layer?","2", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Network layer?","3", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Transport layer?","4", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Session layer?","5", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Presentation layer?","6", "https://en.wikipedia.org/wiki/OSI_model"),
("What numerical layer of the OSI Model is also known as the Application layer?","7", "https://en.wikipedia.org/wiki/OSI_model")]

# True/False questions about Services.
services = [("True or False? TCP is a connection-oriented protocol?","True", "https://en.wikipedia.org/wiki/Transmission_Control_Protocol"),
("True or False? UDP is a connection-less protocol?","True", "https://en.wikipedia.org/wiki/User_Datagram_Protocol"),
("True or False? If you cared more about speed and less about reliability, than you should use TCP.","False", "https://www.cloudflare.com/learning/ddos/glossary/user-datagram-protocol-udp/"),
("True or False? TCP establishes connections using something known as the 4-way handshake.","False", "https://www.cloudflare.com/learning/ddos/glossary/tcp-ip/"),
("True or False? The TCP 3-way handshake consists of the following flags: SYN, SYN-ACK, ACK.","True", "https://www.cloudflare.com/learning/ddos/glossary/tcp-ip/"),
("True or False? Since Telnet is an encrypted protocol, you don't need to worry about anyone sniffing your traffic when logging into your applications.","False", "https://www.omnisecu.com/tcpip/why-telnet-is-not-secure.php")]

def combineQuestions():
    triviaQuestions = aws
    triviaQuestions.extend(commonPorts)
    triviaQuestions.extend(forensics)
    triviaQuestions.extend(linux)
    triviaQuestions.extend(magic)
    triviaQuestions.extend(malware)
    triviaQuestions.extend(numbers)
    triviaQuestions.extend(osiModel)
    triviaQuestions.extend(services)
    return triviaQuestions

def menu():
    # show menu
    print("""
   ____      _                 ____                       _ _           _____     _       _       
  / ___|   _| |__   ___ _ __  / ___|  ___  ___ _   _ _ __(_) |_ _   _  |_   _| __(_)_   _(_) __ _ 
 | |  | | | | '_ \ / _ \ '__| \___ \ / _ \/ __| | | | '__| | __| | | |   | || '__| \ \ / / |/ _` |
 | |__| |_| | |_) |  __/ |     ___) |  __/ (__| |_| | |  | | |_| |_| |   | || |  | |\ V /| | (_| |
  \____\__, |_.__/ \___|_|    |____/ \___|\___|\__,_|_|  |_|\__|\__, |   |_||_|  |_| \_/ |_|\__,_|
       |___/                                                    |___/                             

Welcome to Cyber Security Trivia!

A gamified cyber security quiz developed by malwaredetective! 

Select an option below:
|-----------------------|---------------------------------------------------------------------------------------|
|   1) Challenge Mode   | An endless runner style trivia game. How long can you last before your lives run out? |
|   2) Zen Mode         | No pressure! Just sit back, relax, and have fun learning more about cyber security!   |
|-----------------------|---------------------------------------------------------------------------------------|
""")
    validInput = False
    gamemode = ""
    while(validInput == False):
        gamemode = input("Select a Game Mode: ")
        if str(gamemode) == "1" or str(gamemode) == "2":
            validInput = True
        else:
            print("That's not a valid selection! Please enter 1 for Challenge Mode or 2 for Zen Mode.\n")
    return gamemode

def scoreboard(totalAttempts, totalScore, totalQuestions, gameMode):
    playerAttempts = totalAttempts
    playerScore = totalScore
    #completionPercentage = totalAttempts/totalQuestions * 100
    completionPercentage = totalAttempts/50 * 100
    if gameMode == "zenMode":
        print("""
  ____                     _                         _ 
 / ___|  ___ ___  _ __ ___| |__   ___   __ _ _ __ __| |
 \___ \ / __/ _ \| '__/ _ \ '_ \ / _ \ / _` | '__/ _` |
  ___) | (_| (_) | | |  __/ |_) | (_) | (_| | | | (_| |
 |____/ \___\___/|_|  \___|_.__/ \___/ \__,_|_|  \__,_|

You solved {} out of {} Cyber Security Trivia Questions! Thanks for playing!
    """.format(playerAttempts, playerScore))
    if gameMode == "challengeMode" and totalAttempts == 50:
        print("""
  ____                     _                         _ 
 / ___|  ___ ___  _ __ ___| |__   ___   __ _ _ __ __| |
 \___ \ / __/ _ \| '__/ _ \ '_ \ / _ \ / _` | '__/ _` |
  ___) | (_| (_) | | |  __/ |_) | (_) | (_| | | | (_| |
 |____/ \___\___/|_|  \___|_.__/ \___/ \__,_|_|  \__,_|

You completed {} rounds of Challenge Mode and solved {} Cyber Security Trivia Questions!

            (_v_)                   
             _|_                    
             | |                    
        |-----+-----|  
        |     #1    |    
        |    HERO   |   
        '-----------'    
        \           /    
         '.       .'   
           |     |    
            .' '.               
           _|___|_                  

Congratulations! You were able to withstand the gauntlet and survive Challenge Mode!
    """.format(playerAttempts, playerScore))
    else:
        print("""
  ____                     _                         _ 
 / ___|  ___ ___  _ __ ___| |__   ___   __ _ _ __ __| |
 \___ \ / __/ _ \| '__/ _ \ '_ \ / _ \ / _` | '__/ _` |
  ___) | (_| (_) | | |  __/ |_) | (_) | (_| | | | (_| |
 |____/ \___\___/|_|  \___|_.__/ \___/ \__,_|_|  \__,_|

You survived {} rounds of Challenge Mode and solved {} Cyber Security Trivia Questions!

You were able to survive through {}% of Challenge Mode. Can you develop your skills and complete the gauntlet? 
    """.format(playerAttempts, playerScore, int(completionPercentage)))

def randomCongrats():
    congratsList = ["That's Correct!","Bingo!","Nailed it!", "Nice work!", "Boom!", "Attaboy!", "Bravo!", "Good job!", "Spot on, keep it up!", "Well done!", "Crushed it!", "Survey says ... Ding, ding, ding!"]
    random.shuffle(congratsList)
    congrats = congratsList[0]
    return congrats

def zenMode():
    print("""
Welcome to Zen Mode! The questions will keep on coming until you get through them all! If you need to tap out early, just input "Exit" to stop the quiz.

Good luck, have fun!
""")
    gameMode = "zenMode"
    triviaQuestions = combineQuestions()
    i = 0 
    totalAttempts = 0
    totalScore = 0
    totalQuestions = len(triviaQuestions)
    random.shuffle(triviaQuestions)

    while i < len(triviaQuestions):
        userInput = input(triviaQuestions[i][0] + " ").lower()
        if userInput.startswith(" "):
            userInput = userInput.replace(" ", "")
        if userInput == "exit":
            break
        if userInput == triviaQuestions[i][1].lower():
            print("\n{}\n".format(randomCongrats()))
            totalScore += 1
            totalAttempts += 1
        else:
            print("\nI'm sorry, that's incorrect. The correct answer was {}. For additional information, reference {}.\n".format(triviaQuestions[i][1], triviaQuestions[i][2]))
            totalAttempts += 1
        i += 1
    scoreboard(totalAttempts, totalScore, totalQuestions, gameMode)

def challengeMode():
    print("""
Welcome to Challenge Mode! You have 3 lives ... 
    
  ,d88b.d88b,    ,d88b.d88b,    ,d88b.d88b,
  88888888888    88888888888    88888888888
  `Y8888888Y'    `Y8888888Y'    `Y8888888Y'
    `Y888Y'        `Y888Y'        `Y888Y' 
      `Y'            `Y'            `Y'         

How long can you survive? Good luck, have fun!
""")
    gameMode = "challengeMode"
    triviaQuestions = combineQuestions()
    i = 0
    totalAttempts = 0
    totalScore = 0
    totalQuestions = len(triviaQuestions)
    playerHearts = 3
    random.shuffle(triviaQuestions)

    #while i < len(triviaQuestions) and playerHearts != 0:
    while i < 50 and playerHearts != 0:
        userInput = input(triviaQuestions[i][0] + " ").lower()
        if userInput.startswith(" "):
            userInput = userInput.replace(" ", "")
        if userInput == "exit":
            break
        if userInput == triviaQuestions[i][1].lower():
            print("\n{}\n".format(randomCongrats()))
            totalScore += 1
            totalAttempts += 1
        else:
            playerHearts = playerHearts -1
            print("\nI'm sorry, that's incorrect. The correct answer was {}. For additional information, reference {}.\n".format(triviaQuestions[i][1], triviaQuestions[i][2]))
            totalAttempts += 1
            if playerHearts == 2:
                print("""
You only have two lives left!!!

  ,d88b.d88b,    ,d88b.d88b, 
  88888888888    88888888888 
  `Y8888888Y'    `Y8888888Y'
    `Y888Y'        `Y888Y'
      `Y'            `Y'                        
                
                """)
            elif playerHearts == 1:
                print("""
Oh no, your down to your last life!

  ,d88b.d88b,   
  88888888888   
  `Y8888888Y'  
    `Y888Y'   
      `Y'                          

                """)
        i += 1
    scoreboard(totalAttempts, totalScore, totalQuestions, gameMode)

# Application Entry Point
def main():
    gamemode = menu()
    if gamemode == "1":
        challengeMode()
    else:
        zenMode()

if __name__ == "__main__":
    main()
