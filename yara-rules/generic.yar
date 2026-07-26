/*
 * generic.yar
 * Cross-platform generic malware indicators.
 * These rules intentionally cast a wider net and may have higher FP rates.
 * Use as supplementary detection alongside family-specific rules.
 */

rule Generic_Base64_Shellcode
{
    meta:
        description = "Detects suspiciously long Base64-encoded blobs (potential shellcode)"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        // Long Base64 string (64+ chars, typical shellcode encoding)
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        filesize < 10MB
        and #b64 >= 1
        and not (
            // Exclude common legitimate file types by extension inference
            // (certs, media — can't check extension in YARA, use as supplemental only)
            uint32(0) == 0x4034B50  // ZIP/DOCX/XLSX/PPTX
        )
}

rule Generic_IRC_Botnet
{
    meta:
        description = "Detects IRC-based botnet communication strings"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $irc1 = "NICK " ascii
        $irc2 = "USER " ascii
        $irc3 = "JOIN #" ascii
        $irc4 = "PRIVMSG" ascii
        $irc5 = "NOTICE" ascii
        $irc6 = "PONG" ascii
        $irc7 = ":!" ascii  // common IRC bot command prefix
        $irc8 = "flood" ascii nocase
        $irc9 = "ddos" ascii nocase
        $irc10 = "spread" ascii nocase

    condition:
        filesize < 10MB
        and 4 of ($irc1, $irc2, $irc3, $irc4, $irc5, $irc6)
        and 1 of ($irc7, $irc8, $irc9, $irc10)
}

rule Generic_Suspicious_Network
{
    meta:
        description = "Detects binaries with multiple suspicious network strings"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $n1 = "User-Agent:" ascii
        $n2 = "POST " ascii
        $n3 = "GET " ascii
        $n4 = "HTTP/1" ascii
        $n5 = "Content-Type:" ascii
        $n6 = "Host:" ascii
        $n7 = "Accept:" ascii
        $n8 = "Cookie:" ascii

        // Suspicious C2 patterns
        $c1 = "/gate.php" ascii
        $c2 = "/panel/" ascii
        $c3 = "/bot.php" ascii
        $c4 = "/command" ascii
        $c5 = "/config." ascii
        $c6 = "/upload.php" ascii
        $c7 = "/report.php" ascii

    condition:
        filesize < 20MB
        and 3 of ($n*)
        and 2 of ($c*)
}

rule Generic_AntiForensics
{
    meta:
        description = "Detects anti-forensics / log-wiping strings across platforms"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $af1 = "HISTFILE=/dev/null" ascii
        $af2 = "HISTSIZE=0" ascii
        $af3 = "unset HISTFILE" ascii
        $af4 = "rm -rf /var/log" ascii
        $af5 = "echo '' > /var/log" ascii
        $af6 = "wevtutil cl" ascii nocase  // Windows event log clear
        $af7 = "Clear-EventLog" ascii nocase
        $af8 = "fsutil usn deletejournal" ascii nocase
        $af9 = "/dev/null" ascii

    condition:
        3 of them
}

rule Generic_Crypto_Operations
{
    meta:
        description = "Detects suspicious combined use of crypto + network + execution APIs"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        $cr1 = "CryptDecrypt" ascii
        $cr2 = "CryptEncrypt" ascii
        $cr3 = "AES" ascii
        $cr4 = "RC4" ascii
        $cr5 = "ChaCha" ascii
        $net1 = "WSAStartup" ascii
        $net2 = "connect" ascii
        $net3 = "send" ascii
        $exec1 = "CreateThread" ascii
        $exec2 = "VirtualAlloc" ascii
        $exec3 = "WriteProcessMemory" ascii

    condition:
        uint16(0) == 0x5A4D
        and 1 of ($cr*)
        and 2 of ($net*)
        and 2 of ($exec*)
}
