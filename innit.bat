rem remove some components
powershell -c Disable-MMAgent -ApplicationLaunchPrefetching -mc
rem disable restore because i personally never use it and think it breaks more things than it fixes and wastes disk space
powershell -c disable-computerrestore -drive "C:\"
rem add ssh
powershell -c Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
powershell -c Set-Service -Name sshd -StartupType "Automatic"
rem start it
powershell -c Start-Service sshd
powershell -c Disable-WindowsErrorReporting

rem update the secure boot blocklist (taken from MS documentation on technet)
mountvol q: /S 
echo y|xcopy %systemroot%\System32\SecureBootUpdates\SKUSiPolicy.p7b q:\EFI\Microsoft\Boot 
mountvol q: /D

rem import saved mitigation settings from documents folder
powershell -c Set-ProcessMitigation -PolicyFilePath "e:\pdf\Settings.xml"

rem remove some features we don't use
dism /online /disable-feature /featurename:"MicrosoftWindowsPowerShellV2Root" /norestart
DISM /Online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"SmbDirect" /NoRestart
DISM /Online /Disable-Feature /FeatureName:"MSRDC-Infrastructure" /NoRestart
dism /online /disable-feature /featurename:"MediaPlayback" /norestart
dism /online /disable-feature /featurename:"WorkFolders-Client" /norestart
dism /online /disable-feature /featurename:"Printing-Foundation-LPRPortMonitor" /norestart
dism /online /disable-feature /featurename:"Printing-Foundation-InternetPrinting-Client" /norestart
dism /online /disable-feature /featurename:"RemoteAssistance" /norestart
dism /online /disable-feature /featurename:"Internet-Explorer-Optional-amd64" /norestart
dism /online /Remove-Capability /CapabilityName:"MathRecognizer~~~~0.0.1.0" /norestart
dism /online /Remove-Capability /CapabilityName:"App.StepsRecorder~~~~0.0.1.0" /norestart

rem configure some bcd options we like
bcdedit /set tscsyncpolicy legacy
bcdedit /deletevalue useplatformclock
bcdedit /set disabledynamictick yes
bcdedit /set lastknowngood yes

rem reset these as the defaults seem to work best and anything else causes issues with ssh loopback for some bizarre reason
netsh interface Teredo set state type=default
netsh interface Teredo set state servername=default

REM WINDOWS NT
rem fix terminal services being weird when you connect remotely
reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services\Client" /v fClientDisableUDP /d 1 /t REG_DWORD /f
rem fix shadow sessions for terminal services that nobody ever wanted
reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services\Client" /v Shadow /d 0 /t REG_DWORD /f
rem disable http printing since not needed
reg add "HKCU\Software\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
rem disable printer driver download, do it manually
reg add "HKCU\Software\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f

rem remove new right click menu
REG add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve

REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f
rem The value of 1 means that the hardening is enabled and 0 means that it’s disabled.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole\AppCompat" /v RequireIntegrityActivationAuthenticationLevel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

reg add "HKLM\software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /d 1 /t REG_DWORD /f
reg add "HKLM\software\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /d 1 /t REG_DWORD /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BackgroundAppGlobalToggle /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v GamePanelStartupTipIndex /t REG_DWORD /d 3 /f 
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v ActivationType /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f 
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInstrumentation /t REG_DWORD /d 1 /f 

rem # Disable Smart App Control
rem # Causes slow app loading issues and sends data to Microsoft
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /t 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Secureboot" /v AvailableUpdates /t REG_DWORD /d 0x10 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v HeapDeCommitFreeBlockThreshold /t REG_DWORD /d 0 /f
REG add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v DisableTsx /t REG_DWORD /d 1 /f

reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableEnterpriseAuthProxy /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v MicrosoftEdgeDataOptIn /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInChangeNotification /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInSettingsUx /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowBuildPreview /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContentEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314563Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalled /t reg_dword /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableWer /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableEngine /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v SbEnable /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Ole\AppCompat" /v RaiseActivationAuthenticationLevel /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Ole\AppCompat" /v RequireIntegrityActivationAuthenticationLevel /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InternetManagement" /v RestrictCommunication /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPublishingWizard /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWebServices /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoOnlinePrintsWizard /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ShowTaskViewButton /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v EnthusiastMode /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v FullPath /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v MultipleInvokePromptMinimum /t REG_DWORD /d 100 /f
reg add "HKCU\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 100 /f
reg add "HKCU\Control Panel\Sound" /v Beep /t REG_SZ /d "no" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableLockScreenAppNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableStartupSound /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager" /v "DisableWpbtExecution" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\cfg" /v DiskPercent /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v UserDuckingPreference /t REG_DWORD /d 3 /f 
rem attempt to prevent windows from replacing your current up to date drivers with outdated microsoft drivers at every update
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f 
rem and prevent it from phoning home which will error out anyways every time
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v DriverUpdateWizardWuSearchEnabled /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f 
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v NoOnlineAssist /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v NoExplicitFeedback /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v NoImplicitFeedback /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMovieMaker" /v WebHelp /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMovieMaker" /v CodecDownload /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMovieMaker" /v WebPublish /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\EventViewer" /v MicrosoftEventVwrDisableLinks /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Internet Connection Wizard" /v ExitOnMSICW /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendRequestAdditionalSoftwareToWER /d 1 /f /t REG_DWORD
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendGenericDriverNotFoundToWER /d 1 /f /t REG_DWORD

REM ERROR REPORTING
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps  /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultConsent /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultOverrideBehavior /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v DoReport /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\PCHealth\HelpSvc" /v MicrosoftKBSearch /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\PCHealth\HelpSvc" /v Headlines /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v DisableHelpSticker /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v DisableMFUTracking /t REG_DWORD /d 1 /f
reg add "HKLM\software\policies\microsoft\edge" /v HubsSidebarEnabled /d 0 /t REG_DWORD /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowCommercialDataPipeline /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v DisableGenericRePorts /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v EnableSmartScreen /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v ConfigureAppInstallControl /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f

REM CLOUD CONTENT
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v IncludeEnterpriseSpotlight /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Messaging" /v AllowMessageSync /t REG_DWORD /d 0 /f

REM WINDOWS SEARCH
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v PrimaryIntranetSearchScopeUrl /t REG_SZ /d "http://www.google.com/search?q={searchTerms}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v SecondaryIntranetSearchScopeUrl /t REG_SZ /d "https://duckduckgo.com/?kae=t&q={searchTerms}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAAD /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAADPathOOBE /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWebOverMeteredConnections /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchSafeSearch /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchPrivacy /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v CortanaConsent /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchSafeSearch /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v EnableDynamicContentInWSB /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows Search\Gather\Windows\SystemIndex" /v ConnectedSearchSafeSearch /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v PreventIndexOnBattery /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsAADCloudSearchEnabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsDeviceSearchHistoryEnabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsMSACloudSearchEnabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v SafeSearchMode /t REG_DWORD /d 0 /f 
rem disable taskbar search box
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /d 'Deny' /t REG_SZ /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /d 'Deny' /t REG_SZ /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /d 'Deny' /t REG_SZ /f 
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v ModelDownloadAllowed /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v VoiceActivationEnableAboveLockscreen /t REG_DWORD /d 3 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ActiveWndTrkTimeout /t REG_DWORD /d 10 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_DWORD /d 30 /f

REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSyncOnPaidNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisablePersonalizationSettingSync /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v HasAccepted /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v AllowLinguisticDataCollection /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v InsightsEnabled /d 0 /t REG_DWORD /f

reg add "HKLM\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v EnableEventTranscript /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d 'Deny' /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v DisableOnline /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v AcceptedPrivacyStatement /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v UsageTracking /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v LocationSyncEnabled /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v AllowSpeechModelUpdate /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendGenericDriverNotFoundToWER /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendRequestAdditionalSoftwareToWER /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v Enabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v Enabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v Enabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v Enabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v Enabled /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncPolicy /d 5 /t REG_DWORD /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /d 0 /t REG_DWORD /f 
rem description: Disables 'Always Read and Scan This Section' in Control Panel for QoL
reg add "HKCU\SOFTWARE\Microsoft\Ease of Access" /v selfscan /d 0 /t REG_DWORD /f 
reg add "HKCU\SOFTWARE\Microsoft\Ease of Access" /v selfvoice /d 0 /t REG_DWORD /f 
rem description: Disables commonly annoying features such as pressing shift 5 times for sticky keys.
reg add "HKCU\Control Panel\Accessibility\HighContrast" /v Flags /d 0 /t REG_DWORD /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /d 0 /t REG_DWORD /f 
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v Flags /d 0 /t REG_DWORD /f 
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /d 0 /t REG_DWORD /f 
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /d 0 /t REG_DWORD /f 
rem # Disable language bar shortcuts
reg add "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /d 3 /t REG_DWORD /f 
reg add "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /d 3 /t REG_DWORD /f 
reg add "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /d 3 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d '%windir%\System32\taskkill.exe' /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AggregatorHost.exe" /v Debugger /t REG_SZ /d '%windir%\System32\taskkill.exe' /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d '%windir%\System32\taskkill.exe' /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FeatureLoader.exe" /v Debugger /t REG_SZ /d '%windir%\System32\taskkill.exe' /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d '%windir%\System32\taskkill.exe' /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfmon.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fontdrvhost.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fontdrvhost.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sihost.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sihost.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 0 /f

reg add  "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{60E6D465-398E-4850-BE86-7EF7620A2377}" /t REG_SZ /d  "v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\system32\svchost.exe|Svc=DiagTrack|Name=Windows  Telemetry|" /f
reg add  "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|"  /f
rem reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f} /v LowerFilters /t REG_MULTI_SZ /d fvevol\0iorate\0rdyboost /f
rem reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 33554432 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BingChatInstaller.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BGAUpsell.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BCILauncher.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v ShippedWithReserves /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v RepairContentServerSource /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v MultipleInvokePromptMinimum /t REG_DWORD /d 100 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v DisableBandwidthThrottling /t REG_DWORD /d 1 /f 
rem description: Improves performance in File Explorer by not automatically determining the folder 'type' (such as pictures) for each folder's content
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v FolderType /t REG_SZ /d "NotSpecified" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler\Maintenance" /v WakeUp /t REG_DWORD /d 0 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /f /v ChatIcon /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d "N" /f
reg add "HKCU\Software\NVIDIA Corporation\NVControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\office\16.0\common" /v sendcustomerdata /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\office\common\clienttelemetry" /v sendtelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\office\16.0\common" /v qmenable /t REG_DWORD /d 0 /f


sc config WdiSystemHost start=disabled
sc config msdtc.exe start=disabled
rem this is to stop the weird explorer.exe crash on restart when a gamepad is connected, will not break controller working in games, weirdly
sc config gameinputsvc start=disabled
sc config DPS start=disabled
sc config PcaSvc start=disabled
sc config DiagTrack start=disabled
sc config diagnosticshub.standardcollector.service start=disabled
sc config ndu start=disabled
sc config netbt start=disabled
sc config telemetry start=disabled
sc config bam start=disabled
sc config dam start=disabled
sc config GraphicsPerfSvc start=disabled
sc config sysmain start=disabled
sc config "AppXSvc" start=disabled
sc config beep start=disabled
sc config GpuEnergyDrv start=disabled
sc config sysmain start=disabled
sc config tcpipreg start=disabled
sc config dmwappushservice start=disabled
sc config lfsvc start=disabled
sc config MapsBroker start=disabled
sc config OneSyncSvc start=disabled
sc config TrkWks start=disabled
sc config PcaSvc start=disabled
sc config WSearch start=disabled
sc config wercplsupport start=disabled
sc config UCPD start=disabled

sc config WdiServiceHost start=demand
sc config WerSvc start=demand
sc config lmhosts start=demand
sc config SharedAccess start=demand
sc config Wecsvc start=demand
sc config BITS start=demand
sc config phonesvc start=demand
sc config SCardSvr start=demand
sc config WbioSrvc start=demand
sc config WMPNetworkSvc start=demand
sc config BTAGService start=demand
sc config BthAvctpSvc start=demand
sc config RtkBtManServ start=demand
sc config WdiSystemHost start=demand
sc config wisvc start=demand
sc config WbioSrvc start=demand
sc config XboxNetApiSvc start=demand
sc config XboxGipSvc start=demand
sc config XblGameSave start=demand
sc config XblAuthManager start=demand

powercfg -h off

fsutil behavior set disableLastAccess 1
fsutil behavior set disable8dot3 1

schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /change /tn "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /disable
schtasks /change /tn "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /disable
schtasks /change /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /disable
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable'
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /change /TN "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /e:false
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /e:false
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /e:false

assoc .bat=batfile
assoc .cmd=batfile
bootsect /nt60 all /force
bootsect /nt60 all /force /mbr

setx POWERSHELL_TELEMETRY_OPTOUT 1
setx DOTNET_CLI_TELEMETRY_OPTOUT 1

net accounts /maxpwage:unlimited

reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.549981C3F5F10_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingNews_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingWeather_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.ECApp_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.GetHelp_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Getstarted_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftEdge_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.People_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Todos_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.Photos_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsAlarms_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsCamera_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsMaps_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.ZuneMusic_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.ZuneVideo_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\microsoft.windowscommunicationsapps_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Advertising.Xaml_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MixedReality.Portal_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MSPaint_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Paint_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsNotepad_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\clipchamp.clipchamp_yxz26nhyzhsrt /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.SecHealthUI_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsCalculator_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftCorporationII.MicrosoftFamily_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Whiteboard_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\microsoft.microsoftskydrive_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftTeamsforSurfaceHub_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftCorporationII.MailforSurfaceHub_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftPowerBIForWindows_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.SkypeApp_kzf8qxf38zg5c /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.OneNote_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.Excel_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.PowerPoint_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.Word_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.DevHome_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.OutlookForWindows_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MSTeams_8wekyb3d8bbwe /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v RSoPLogging /t REG_DWORD /d 0 /f 
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d} /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f 
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService /v EnableDeviceHealthAttestationService /t REG_DWORD /d 0 /f
powershell -c "Get-AppxPackage -AllUsers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftStickyNotes" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *OneDrive* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "OneDrive" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Spotify* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Spotify" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *SecureAssessmentBrowser* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "SecureAssessmentBrowser" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *PeopleExperienceHost* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "PeopleExperienceHost" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Windows.Photos* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Windows.Photos" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.WindowsCamera* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.WindowsCamera" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MicrosoftWindows.Client.WebExperience* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftWindows.Client.WebExperience" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.WindowsAlarms* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.WindowsAlarms" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.WindowsMaps* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.WindowsMaps" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *microsoft.windowscommunicationsapps* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "microsoft.windowscommunicationsapps" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.People* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.People" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.BingNews* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.BingNews" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.BingSearch* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.BingSearch" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.BingWeather* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.BingWeather" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.WindowsFeedbackHub" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.GetHelp* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.GetHelp" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.GetStarted* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.GetStarted" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.PowerAutomateDesktop* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.PowerAutomateDesktop" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.549981C3F5F10* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.549981C3F5F10" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftCorporationII.QuickAssist" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MicrosoftCorporationII.MicrosoftFamily* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftCorporationII.MicrosoftFamily" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.ZuneMusic* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.ZuneMusic" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.ZuneVideo* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.ZuneVideo" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.WindowsSoundRecorder" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Clipchamp.Clipchamp* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Clipchamp.Clipchamp" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Whiteboard* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Whiteboard" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *microsoft.microsoftskydrive* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "microsoft.microsoftskydrive" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.MicrosoftTeamsforSurfaceHub* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftTeamsforSurfaceHub" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MicrosoftCorporationII.MailforSurfaceHub* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftCorporationII.MailforSurfaceHub" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.MicrosoftPowerBIForWindows* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.SkypeApp* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.SkypeApp" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftOfficeHub" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Office.Excel* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Office.Excel" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Office.PowerPoint* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Office.PowerPoint" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Office.Word* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Office.Word" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Office.OneNote* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Office.OneNote" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *OutlookForWindows* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "OutlookForWindows" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *OutlookPWA* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "OutlookPWA" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Microsoft3DViewer" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Advertising* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Advertising" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MixedReality.Portal* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MixedReality.Portal" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.MSPaint* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MSPaint" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MicrosoftTeams* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftTeams" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MSTeams* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MSTeams" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *DevHome* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "DevHome" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *FlipGrid* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "FlipGrid" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.Xbox* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.Xbox" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.GamingApp* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.GamingApp" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *Microsoft.YourPhone* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.YourPhone" | Remove-AppxProvisionedPackage -Online"
powershell -c "Get-AppxPackage -AllUsers *MicrosoftWindows.Client.AIX* | Remove-AppxPackage"
powershell -c "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftWindows.Client.AIX" | Remove-AppxProvisionedPackage -Online"

powershell -c '[System.Environment]::SetEnvironmentVariable("KnownFolder.Pictures", "D:\jpg", "User")'
powershell -c '[System.Environment]::SetEnvironmentVariable("KnownFolder.Downloads", "e:\downloads", "User")'
powershell -c '[System.Environment]::SetEnvironmentVariable("KnownFolder.Documents", "d:\pdf", "User")'
powershell -c '[System.Environment]::SetEnvironmentVariable("KnownFolder.Music", "d:\mp3", "User")'
powershell -c '[System.Environment]::SetEnvironmentVariable("KnownFolder.Videos", "e:\video", "User")'
powershell -c Set-MpPreference -EnableNetworkProtection Enabled -Force
rem set this to disabled to not flag my sys admin utils as unwanted apps, change if desired
powershell -c Set-MpPreference -PUAProtection Disabled -Force
powershell -c Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
powershell -c Set-ItemProperty Verified -Path "$PathToCUExplorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
powershell -c Set-ItemProperty Verified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
powershell -c Disable-SearchAppForUnknownExt
powershell -c Set-ItemProperty Verified -Path "$PathToCUExplorerAdvanced" -Name "HideFileExt" -Type DWord -Value 0
powershell -c Set-ItemProperty Verified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
powershell -c Set-ItemProperty Verified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
powershell -c Set-ItemProperty Verified -Path "$PathToLMPoliciesMRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 0
powershell -c setx /M MP_FORCE_USE_SANDBOX 1
powershell -c Set-ItemProperty Verified -Path "$PathToCUGameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
powershell -c Set-ItemProperty Verified -Path "$PathToCUGameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
powershell -c Set-ItemProperty Verified -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "GPU Priority" -Type DWord -Value 8 # Default: 8
powershell -c Set-ItemProperty Verified -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "Priority" -Type DWord -Value 6 # Default: 2
powershell -c Set-ItemProperty Verified -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "Scheduling Category" -Type String -Value "High" # Default: "Medium"
