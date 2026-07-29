rule AutoGen_Unknown_3652b0a2
{
    meta:
        description = "Auto-generated rule for unknown_3652b0a2 (honeypot telemetry)"
        author      = "honeypot-bot"
        date        = "2026-07-29"
        auto_generated = true
        sample_sha256 = "3652b0a2453858df736e1ff16e04120b296641b22f98643a7eca6f4f981c0c3c"
        reference1  = "https://www.virustotal.com/gui/file-analysis/N2JlNzk5Y2Q5N2Y0MjRjODIwYjRlZmQ1YjZiZDRhMmY6MTc4NTM0ODk5MQ=="
        reference2  = "https://bazaar.abuse.ch/sample//"

    strings:
        $s1 = "NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 \"" ascii nocase
        $s2 = "NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 !" ascii nocase
        $s3 = "NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" ascii nocase
        $s4 = "NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii nocase
        $s5 = "HStoreInstaller.Acquisition.WpmInstaller+<FindPackageInCatalogAsync>d__20" ascii nocase
        $s6 = "QSystem.Runtime, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" ascii nocase
        $s7 = "Ehttp://www.microsoft.com/pkiops/certs/MicCodSigPCA2011_2011-07-08.crt0" ascii nocase
        $s8 = "Kmscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii nocase
        $s9 = "IStoreInstaller.ViewModels.InstallViewModel+<WaitForSFEdgeTaskAsync>d__143" ascii nocase
        $s10 = "Ehttp://crl.microsoft.com/pki/crl/products/MicRooCerAut_2010-06-23.crl0Z" ascii nocase
        $s11 = "Fhttp://crl.microsoft.com/pki/crl/products/MicMarPCA2011_2011-03-28.crl0[" ascii nocase
        $s12 = "KStoreInstaller, Version=22607.714.3.0, Culture=neutral, PublicKeyToken=null" ascii nocase
        $s13 = "IStoreInstaller.Acquisition.WpmInstaller+<ResumeExistingInstallAsync>d__15" ascii nocase
        $s14 = "GStoreInstaller.ViewModels.InstallViewModel+<RetrieveMaturityTask>d__140" ascii nocase
        $s15 = "HStoreInstaller.ViewModels.InstallViewModel+<AttemptProductInstall>d__137" ascii nocase
        $s16 = "HStoreInstaller.Acquisition.WuInstaller+<GetProductEntitlementAsync>d__17" ascii nocase
        $s17 = "FStoreInstaller.ViewModels.InstallViewModel+<InstallProductAsync>d__146" ascii nocase
        $s18 = "IStoreInstaller.Acquisition.WuAllUsersInstaller+<CheckForUpdatesAsync>d__6" ascii nocase
        $s19 = "IStoreInstaller.Acquisition.WuAllUsersInstaller+<OnItemStatusChanged>d__10" ascii nocase
        $s20 = "NStoreInstaller.ViewModels.InstallViewModel+<WaitForEntitlementTaskAsync>d__144" ascii nocase

    condition:
        3 of ($s*)
}
