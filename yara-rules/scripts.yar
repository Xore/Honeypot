/*
 * scripts.yar
 * Detects malicious shell scripts, PowerShell droppers, Python backdoors,
 * and VBScript/JScript stagers collected via honeypot.
 */

rule Shell_Downloader_Generic
{
    meta:
        description = "Detects generic shell downloader / dropper script"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $dl1 = "wget " ascii
        $dl2 = "curl " ascii
        $dl3 = "chmod +x" ascii
        $dl4 = "chmod 777" ascii
        $dl5 = "/tmp/" ascii
        $dl6 = ">/dev/null 2>&1" ascii
        $dl7 = "2>/dev/null" ascii
        $dl8 = "base64 -d" ascii
        $dl9 = "bash -c" ascii
        $dl10 = "sh -c" ascii

    condition:
        filesize < 500KB
        and 4 of them
}

rule Shell_Persistence_Mechanism
{
    meta:
        description = "Detects shell script establishing persistence"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $p1 = "crontab -e" ascii
        $p2 = "/etc/cron" ascii
        $p3 = "@reboot" ascii
        $p4 = "/etc/rc.local" ascii
        $p5 = "/etc/init.d/" ascii
        $p6 = ".bashrc" ascii
        $p7 = ".bash_profile" ascii
        $p8 = ".profile" ascii
        $p9 = "systemctl enable" ascii
        $p10 = "chkconfig" ascii

    condition:
        filesize < 500KB
        and 3 of them
}

rule PowerShell_Encoded_Command
{
    meta:
        description = "Detects PowerShell scripts using encoded/obfuscated commands"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $ps1 = "-EncodedCommand" ascii nocase
        $ps2 = "-enc " ascii nocase
        $ps3 = "-e " ascii
        $ps4 = "FromBase64String" ascii
        $ps5 = "[Convert]::" ascii
        $ps6 = "IEX" ascii
        $ps7 = "Invoke-Expression" ascii nocase
        $ps8 = "DownloadString" ascii
        $ps9 = "DownloadFile" ascii
        $ps10 = "Net.WebClient" ascii
        $ps11 = "bypass" ascii nocase
        $ps12 = "-nop" ascii nocase
        $ps13 = "-NonInteractive" ascii nocase
        $ps14 = "-WindowStyle Hidden" ascii nocase

    condition:
        filesize < 5MB
        and (
            (($ps6 or $ps7) and ($ps4 or $ps5)) or
            ($ps1 or $ps2) or
            ($ps3 and ($ps4 or $ps5)) or
            (2 of ($ps8, $ps9, $ps10) and ($ps11 or $ps12 or $ps13 or $ps14))
        )
}

rule PowerShell_Reverse_Shell
{
    meta:
        description = "Detects PowerShell reverse shell patterns"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $r1 = "Net.Sockets.TCPClient" ascii
        $r2 = "System.Net.Sockets" ascii
        $r3 = "StreamReader" ascii
        $r4 = "StreamWriter" ascii
        $r5 = "GetStream" ascii
        $r6 = "cmd.exe" ascii nocase
        $r7 = "powershell.exe" ascii nocase
        $r8 = "Invoke-Item" ascii

    condition:
        filesize < 5MB
        and ($r1 or $r2) and $r5 and ($r3 or $r4) and ($r6 or $r7 or $r8)
}

rule Python_Backdoor
{
    meta:
        description = "Detects Python backdoor / RAT script patterns"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $py1 = "import socket" ascii
        $py2 = "import subprocess" ascii
        $py3 = "import os" ascii
        $py4 = "s.connect" ascii
        $py5 = "subprocess.Popen" ascii
        $py6 = "subprocess.call" ascii
        $py7 = "os.system" ascii
        $py8 = "base64.b64decode" ascii
        $py9 = "exec(" ascii
        $py10 = "eval(" ascii
        $py11 = "__import__" ascii

    condition:
        filesize < 5MB
        and $py1
        and ($py2 or $py3)
        and ($py4 or $py5 or $py6 or $py7)
        and ($py8 or $py9 or $py10 or $py11)
}

rule VBScript_Dropper
{
    meta:
        description = "Detects malicious VBScript dropper / stager"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $v1 = "WScript.Shell" ascii nocase
        $v2 = "Shell.Application" ascii nocase
        $v3 = "CreateObject" ascii nocase
        $v4 = "WScript.Run" ascii nocase
        $v5 = "Scripting.FileSystemObject" ascii nocase
        $v6 = "XMLHTTP" ascii nocase
        $v7 = "ADODB.Stream" ascii nocase
        $v8 = "powershell" ascii nocase
        $v9 = "cmd.exe" ascii nocase
        $v10 = "RegWrite" ascii nocase

    condition:
        filesize < 5MB
        and $v3 and 3 of ($v1, $v2, $v4, $v5, $v6, $v7, $v8, $v9, $v10)
}
