rule AutoGen_Chatgpt_installer_exe
{
    meta:
        description = "Auto-generated rule for chatgpt_installer_exe (honeypot telemetry)"
        author      = "honeypot-bot"
        date        = "2026-07-31"
        auto_generated = true
        sample_sha256 = "3652b0a2453858df736e1ff16e04120b296641b22f98643a7eca6f4f981c0c3c"
        file_types  = "Win32 EXE"
        reference1  = "https://www.virustotal.com/gui/file/3652b0a2453858df736e1ff16e04120b296641b22f98643a7eca6f4f981c0c3c"
        reference2  = "https://bazaar.abuse.ch/sample/3652b0a2453858df736e1ff16e04120b296641b22f98643a7eca6f4f981c0c3c/"

    strings:
        $s1 = "shell9http://schemas.microsoft.com/netfx/2009/xaml/presentation" ascii nocase
        $s2 = "mc;http://schemas.openxmlformats.org/markup-compatibility/2006" ascii nocase
        $s3 = "Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -->" ascii nocase
        $s4 = "<dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii nocase
        $s5 = "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" ascii nocase
        $s6 = "DStoreInstaller.Acquisition.WpmInstaller+<ConnectToPackageAsync>d__21" ascii nocase
        $s7 = "BStoreInstaller.Acquisition.WuInstaller+<CheckForUpdatesAsync>d__12" ascii nocase
        $s8 = "CStoreInstaller.Acquisition.WpmInstaller+<CheckForUpdatesAsync>d__14" ascii nocase
        $s9 = "BStoreInstaller.ViewModels.InstallViewModel+<CallSFEdgeAsync>d__142" ascii nocase
        $s10 = "CStoreInstaller.Helpers.UetHelper+<EnsureStoreWinMdLoadedAsync>d__19" ascii nocase
        $s11 = "HStoreInstaller.Acquisition.WpmInstaller+<FindPackageInCatalogAsync>d__20" ascii nocase
        $s12 = "BStoreInstaller.Acquisition.WuInstaller+<CheckForLicenseAsync>d__11" ascii nocase
        $s13 = "=pack://application:,,,/Resources/DefaultFocusVisualStyle.xaml?" ascii nocase
        $s14 = "EStoreInstaller.ViewModels.InstallViewModel+<LaunchProductAsync>d__165" ascii nocase
        $s15 = "?StoreInstaller.Acquisition.WuInstaller+<BeginInstallAsync>d__13" ascii nocase
        $s16 = "IStoreInstaller.ViewModels.InstallViewModel+<WaitForSFEdgeTaskAsync>d__143" ascii nocase
        $s17 = "CStoreInstaller.Acquisition.WpmInstaller+<GetInstallStateAsync>d__19" ascii nocase
        $s18 = "IStoreInstaller.Acquisition.WpmInstaller+<ResumeExistingInstallAsync>d__15" ascii nocase
        $s19 = "BStoreInstaller.Acquisition.WpmInstaller+<WaitForInstallAsync>d__22" ascii nocase
        $s20 = "GStoreInstaller.ViewModels.InstallViewModel+<RetrieveMaturityTask>d__140" ascii nocase

    condition:
        8 of ($s*)
}
