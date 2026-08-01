/*
 * malicious_docs.yar
 * Detects malicious Office documents (macro droppers) and PDF exploits
 * collected via document-lure honeypot surfaces.
 */

rule Office_Macro_Dropper
{
    meta:
        description = "Detects Office document with suspicious macro dropper indicators"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        // OLE / OOXML macro triggers
        $m1 = "AutoOpen" ascii nocase
        $m2 = "AutoExec" ascii nocase
        $m3 = "Document_Open" ascii nocase
        $m4 = "Workbook_Open" ascii nocase
        $m5 = "Auto_Open" ascii nocase

        // Suspicious macro actions
        $a1 = "Shell" ascii
        $a2 = "WScript" ascii nocase
        $a3 = "PowerShell" ascii nocase
        $a4 = "cmd.exe" ascii nocase
        $a5 = "URLDownloadToFile" ascii
        $a6 = "CreateObject" ascii nocase
        $a7 = "XMLHTTP" ascii nocase
        $a8 = "Environ(" ascii nocase
        $a9 = "Chr(" ascii

        // OLE2 magic bytes
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // OOXML indicators
        $ooxml1 = "xl/vbaProject.bin" ascii
        $ooxml2 = "word/vbaProject.bin" ascii

    condition:
        filesize < 50MB
        and (
            ($ole_magic and 1 of ($m*) and 2 of ($a*)) or
            (($ooxml1 or $ooxml2) and 1 of ($m*)) or
            (1 of ($m*) and 3 of ($a*))
        )
}

rule PDF_JavaScript_Exploit
{
    meta:
        description = "Detects malicious JavaScript embedded in PDF files"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"

    strings:
        // PDF magic
        $pdf_magic = { 25 50 44 46 }  // %PDF

        // Malicious PDF JS
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $js3 = "eval(" ascii
        $js4 = "unescape(" ascii
        $js5 = "String.fromCharCode" ascii
        $js6 = "shellcode" ascii nocase
        $js7 = "this.exportDataObject" ascii
        $js8 = "util.printf" ascii
        $js9 = "getAnnots" ascii
        $js10 = "/Launch" ascii
        $js11 = "/OpenAction" ascii
        $js12 = "/EmbeddedFile" ascii

    condition:
        $pdf_magic at 0
        and (
            (($js1 or $js2) and $js3 and ($js4 or $js5 or $js6)) or
            ($js10 or $js11) or
            ($js7 or $js8 or $js9) or
            ($js12 and ($js1 or $js2))
        )
}

rule Office_CVE_Exploit_Indicators
{
    meta:
        description = "Detects common CVE exploit indicators in Office documents (CVE-2017-11882, CVE-2017-0199, Follina)"
        author      = "Honeypot-YARA"
        date        = "2024-01-01"
        reference   = "CVE-2017-11882, CVE-2017-0199, CVE-2022-30190"

    strings:
        // CVE-2017-0199: HTA/http external reference
        $ref1 = "http://" ascii
        $ref2 = ".hta" ascii nocase
        $ref3 = "mshta" ascii nocase

        // CVE-2017-11882: Equation Editor exploit pattern
        $eq1 = { 45 71 75 61 74 69 6F 6E }  // "Equation"
        $eq2 = "Microsoft Equation" ascii nocase

        // Follina (CVE-2022-30190): ms-msdt URI
        $msdt1 = "ms-msdt:" ascii nocase
        $msdt2 = "msdt.exe" ascii nocase
        $msdt3 = "PCWDiagnostic" ascii nocase

        // RTF exploit marker
        $rtf_magic = { 7B 5C 72 74 66 }  // {\rtf
        $rtf_obj = "\\objdata" ascii nocase

    condition:
        filesize < 50MB
        and (
            ($eq1 or $eq2) or
            ($msdt1 or ($msdt2 and $msdt3)) or
            ($ref2 and $ref3 and $ref1) or
            ($rtf_magic at 0 and $rtf_obj)
        )
}
