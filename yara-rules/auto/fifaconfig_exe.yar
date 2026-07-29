rule AutoGen_Fifaconfig_exe
{
    meta:
        description = "Auto-generated rule for fifaconfig_exe (honeypot telemetry)"
        author      = "honeypot-bot"
        date        = "2026-07-29"
        auto_generated = true
        sample_sha256 = "0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e"
        file_types  = "Win32 EXE"
        reference1  = "https://www.virustotal.com/gui/file/0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e"
        reference2  = "https://bazaar.abuse.ch/sample/0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e/"

    strings:
        $s1 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii nocase
        $s2 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii nocase
        $s3 = "System.Runtime.CompilerServices" ascii nocase
        $s4 = "CompilationRelaxationsAttribute" ascii nocase
        $s5 = "WrapNonExceptionThrows" ascii nocase
        $s6 = "AssemblyConfigurationAttribute" ascii nocase
        $s7 = "System.Runtime.InteropServices" ascii nocase
        $s8 = "GetCommandLineArgs" ascii nocase
        $s9 = "FileSystemInfo" ascii nocase
        $s10 = "RuntimeCompatibilityAttribute" ascii nocase
        $s11 = "_CorExeMain" ascii nocase
        $s12 = "AssemblyDescriptionAttribute" ascii nocase
        $s13 = "AssemblyCompanyAttribute" ascii nocase
        $s14 = "AssemblyCopyrightAttribute" ascii nocase
        $s15 = "GetLaunchExeFilename" ascii nocase
        $s16 = "FrameworkDisplayName" ascii nocase
        $s17 = "AssemblyFileVersionAttribute" ascii nocase
        $s18 = "AssemblyTrademarkAttribute" ascii nocase
        $s19 = "TargetFrameworkAttribute" ascii nocase
        $s20 = "AssemblyProductAttribute" ascii nocase

    condition:
        3 of ($s*)
}
