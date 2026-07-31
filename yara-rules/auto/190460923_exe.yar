rule AutoGen_190460923_exe
{
    meta:
        description = "Auto-generated rule for 190460923_exe (honeypot telemetry)"
        author      = "honeypot-bot"
        date        = "2026-07-31"
        auto_generated = true
        sample_sha256 = "0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e"
        file_types  = "Win32 EXE"
        reference1  = "https://www.virustotal.com/gui/file/0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e"
        reference2  = "https://bazaar.abuse.ch/sample/0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e/"

    strings:
        $s1 = "set_WorkingDirectory" ascii nocase
        $s2 = "get_CurrentDomain" ascii nocase
        $s3 = "get_BaseDirectory" ascii nocase
        $s4 = "GetEnvironmentVariable" ascii nocase
        $s5 = "DirectoryInfo" ascii nocase
        $s6 = "ProcessStartInfo" ascii nocase
        $s7 = "DebuggingModes" ascii nocase
        $s8 = "set_FileName" ascii nocase
        $s9 = "get_FullName" ascii nocase
        $s10 = "DoAutoLaunch" ascii nocase
        $s11 = "ReadToEnd" ascii nocase
        $s12 = "AppDomain" ascii nocase
        $s13 = "StringSplitOptions" ascii nocase
        $s14 = "StartsWith" ascii nocase
        $s15 = "TextReader" ascii nocase
        $s16 = "argsToParse" ascii nocase
        $s17 = "StreamReader" ascii nocase
        $s18 = "H:\\C#\\fifaconfig\\fifaconfig\\obj\\Release\\fifaconfig.pdb" ascii nocase
        $s19 = "</security>" ascii nocase
        $s20 = "</requestedPrivileges>" ascii nocase

    condition:
        8 of ($s*)
}
