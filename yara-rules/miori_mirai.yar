/*
 * miori_mirai.yar
 * Detects Miori and Mirai botnet variants collected via honeypot.
 * Miori is a Mirai fork targeting IoT devices with hardcoded credential
 * brute-force, DDoS capability, and a distinct C2 protocol.
 */

rule Mirai_Generic
{
    meta:
        description = "Detects generic Mirai botnet ELF binary indicators"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"
        reference   = "https://github.com/jgamblin/Mirai-Source-Code"
        family      = "Mirai"

    strings:
        // Mirai hardcoded credential table strings
        $s1  = "root" fullword
        $s2  = "admin" fullword
        $s3  = "vizxv" ascii
        $s4  = "xmhdipc" ascii
        $s5  = "juantech" ascii
        $s6  = "jvbzd" ascii
        $s7  = "Zte521" ascii
        $s8  = "hi3518" ascii
        $s9  = "1234" ascii
        $s10 = "default" ascii

        // DDoS attack strings
        $ddos1 = "ATTACK_UDP_PLAIN" ascii
        $ddos2 = "ATTACK_UDP_BYPASS" ascii
        $ddos3 = "ATTACK_TCP_SYN" ascii
        $ddos4 = "ATTACK_TCP_ACK" ascii
        $ddos5 = "ATTACK_APP_HTTP" ascii

        // C2 / scanner strings
        $c2_1 = "/bin/busybox" ascii
        $c2_2 = "MIRAI" ascii
        $c2_3 = "LZRD" ascii
        $c2_4 = "nigger" ascii  // found in many Mirai variants
        $c2_5 = "Botnet" ascii

    condition:
        uint32(0) == 0x464C457F  // ELF magic
        and filesize < 2MB
        and (
            (3 of ($ddos*)) or
            (2 of ($c2*) and 3 of ($s*)) or
            (all of ($ddos*) and 1 of ($c2*))
        )
}

rule Miori_Variant
{
    meta:
        description = "Detects Miori-specific strings distinguishing it from base Mirai"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"
        reference   = "https://blog.trendmicro.com/trendlabs-security-intelligence/miori-new-variant-of-mirai-uses-php-exploit/"
        family      = "Miori"

    strings:
        $m1 = "MIORI" ascii
        $m2 = "miori" ascii nocase
        $m3 = "http://" ascii
        $m4 = "/bin/sh" ascii
        $m5 = "wget" ascii
        $m6 = "curl" ascii
        $m7 = "chmod 777" ascii
        $m8 = "tftp" ascii

        // Miori download-and-exec pattern
        $dl1 = "wget -O-" ascii
        $dl2 = "curl -o" ascii
        $dl3 = ">>/tmp/" ascii
        $dl4 = ">/tmp/" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 5MB
        and (
            $m1 or $m2 or
            (2 of ($dl*) and 2 of ($m3, $m4, $m5, $m6, $m7, $m8))
        )
}

rule Mirai_CNC_Communication
{
    meta:
        description = "Detects Mirai C2 communication setup patterns in ELF binaries"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"
        family      = "Mirai"

    strings:
        // Loader strings
        $load1 = "asshole" ascii
        $load2 = "hacktheplanet" ascii
        $load3 = "sora" ascii
        $load4 = "hoho" ascii
        $load5 = "Mozi" ascii nocase
        $load6 = "BOTNET" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 2MB
        and any of ($load*)
}

rule Mirai_Downloader_Script
{
    meta:
        description = "Detects Mirai/Miori shell downloader scripts used in initial infection"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"
        family      = "Mirai"

    strings:
        $dl1 = "wget http" ascii
        $dl2 = "curl http" ascii
        $dl3 = "chmod +x" ascii
        $dl4 = "chmod 777" ascii
        $dl5 = "/tmp/" ascii
        $dl6 = ">/dev/null" ascii
        $dl7 = "busybox" ascii
        $dl8 = "rm -rf" ascii
        $dl9 = "./" ascii

    condition:
        filesize < 50KB
        and 5 of them
}
