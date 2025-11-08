#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configures Microsoft Edge for minimal, user-focused browsing experience
.DESCRIPTION
    Sets Edge to start with about:blank, use DuckDuckGo as default search,
    and disables Microsoft's intrusive features and data collection
.AUTHOR
    Infrastructure Admin Script
#>

Write-Host "Configuring Microsoft Edge for minimal browsing..." -ForegroundColor Cyan

# Registry paths
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$EdgeUserPath = "HKCU:\SOFTWARE\Microsoft\Edge\Main"

# Ensure policy registry path exists
if (!(Test-Path $EdgePolicyPath)) {
    New-Item -Path $EdgePolicyPath -Force | Out-Null
    Write-Host "✓ Created Edge policy registry path" -ForegroundColor Green
}

# Core browsing settings
Write-Host "Setting core browsing preferences..." -ForegroundColor Yellow

# Start and new tab pages
Set-ItemProperty -Path $EdgePolicyPath -Name "HomepageLocation" -Value "about:blank" -Type String
Set-ItemProperty -Path $EdgePolicyPath -Name "NewTabPageLocation" -Value "about:blank" -Type String
Set-ItemProperty -Path $EdgePolicyPath -Name "RestoreOnStartup" -Value 1 -Type DWord
Set-ItemProperty -Path $EdgePolicyPath -Name "HomepageIsNewTabPage" -Value 0 -Type DWord
Set-ItemProperty -Path $EdgePolicyPath -Name "NewTabPageSetFeedType" -Value 0 -Type DWord  # Disable MSN feed
Set-ItemProperty -Path $EdgePolicyPath -Name "NewTabPageContentEnabled" -Value 0 -Type DWord  # Disable content on new tab
Set-ItemProperty -Path $EdgePolicyPath -Name "NewTabPageQuickLinksEnabled" -Value 0 -Type DWord  # Disable quick links

# Default search engine to DuckDuckGo
Set-ItemProperty -Path $EdgePolicyPath -Name "DefaultSearchProviderEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $EdgePolicyPath -Name "DefaultSearchProviderName" -Value "DuckDuckGo" -Type String
Set-ItemProperty -Path $EdgePolicyPath -Name "DefaultSearchProviderSearchURL" -Value "https://duckduckgo.com/?q={searchTerms}" -Type String

Write-Host "✓ Configured about:blank start/new tab pages" -ForegroundColor Green
Write-Host "✓ Set DuckDuckGo as default search engine" -ForegroundColor Green

# Disable Microsoft intrusive features
Write-Host "Disabling Microsoft tracking and bloat..." -ForegroundColor Yellow

$DisableFeatures = @{
    "PersonalizationReportingEnabled" = 0      # Disable personalization data
    "SearchSuggestEnabled" = 0                 # Disable search suggestions
    "ShowMicrosoftRewards" = 0                 # Disable rewards notifications
    "EdgeShoppingAssistantEnabled" = 0         # Disable shopping assistant
    "WebWidgetAllowed" = 0                     # Disable web widgets
    "HubsSidebarEnabled" = 0                   # Disable sidebar
    "EdgeCollectionsEnabled" = 0               # Disable collections
    "ConfigureDoNotTrack" = 1                  # Enable Do Not Track
    "BlockThirdPartyCookies" = 1               # Block 3rd party cookies
    "PasswordManagerEnabled" = 0               # Disable password manager
    "AutofillAddressEnabled" = 0               # Disable address autofill
    "AutofillCreditCardEnabled" = 0            # Disable credit card autofill
    "SpellcheckEnabled" = 0                    # Disable spellcheck
    "TranslateEnabled" = 0                     # Disable translate
    "ShowHomeButton" = 0                       # Hide home button (prevents MSN access)
    "EdgeAssetDeliveryServiceEnabled" = 0      # Disable asset delivery (news/ads)
    "DiagnosticData" = 0                       # Disable diagnostic data
    "EdgeEnhanceImagesEnabled" = 0             # Disable image enhancement
    "EfficiencyMode" = 0                       # Disable efficiency mode prompts
}

foreach ($setting in $DisableFeatures.GetEnumerator()) {
    Set-ItemProperty -Path $EdgePolicyPath -Name $setting.Key -Value $setting.Value -Type DWord
}

Write-Host "✓ Disabled tracking, suggestions, and bloat features" -ForegroundColor Green

# Additional privacy settings
Set-ItemProperty -Path $EdgePolicyPath -Name "MetricsReportingEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $EdgePolicyPath -Name "UserFeedbackAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path $EdgePolicyPath -Name "DefaultCookiesSetting" -Value 4 -Type DWord  # Block cookies by default

Write-Host "✓ Enhanced privacy settings applied" -ForegroundColor Green

# Final message
Write-Host "`nEdge configuration complete!" -ForegroundColor Cyan
Write-Host "   Start page: about:blank" -ForegroundColor White
Write-Host "   New tabs: about:blank (MSN feed disabled)" -ForegroundColor White
Write-Host "   Search: DuckDuckGo" -ForegroundColor White
Write-Host "   Tracking: Disabled" -ForegroundColor White
Write-Host "   Microsoft bloat: Removed" -ForegroundColor White
Write-Host "`nRestart Edge to apply all changes" -ForegroundColor Yellow