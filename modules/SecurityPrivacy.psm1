<#
.SYNOPSIS
    Security and Privacy functions for Windows Toolbox

.DESCRIPTION
    Functions for browser hardening and privacy configurations
#>

# Import common functions
$commonModule = Join-Path $PSScriptRoot 'Common.psm1'
Import-Module $commonModule -Force

#region Microsoft Edge Hardening

<#
.SYNOPSIS
    Hardens Microsoft Edge with privacy-focused settings
#>
function Set-EdgePrivacySettings {
    [CmdletBinding()]
    param()

    Write-LogMessage "Configuring Microsoft Edge for privacy and minimal browsing..." -Level Info -Component 'EdgeHardening'

    $edgePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

    # Ensure policy path exists
    if (-not (Test-Path $edgePolicyPath)) {
        New-Item -Path $edgePolicyPath -Force | Out-Null
        Write-LogMessage "Created Edge policy registry path" -Level Info -Component 'EdgeHardening'
    }

    # Start and new tab pages
    Write-LogMessage "Setting core browsing preferences..." -Level Info -Component 'EdgeHardening'

    Set-ItemProperty -Path $edgePolicyPath -Name 'HomepageLocation' -Value 'about:blank' -Type String
    Set-ItemProperty -Path $edgePolicyPath -Name 'NewTabPageLocation' -Value 'about:blank' -Type String
    Set-ItemProperty -Path $edgePolicyPath -Name 'RestoreOnStartup' -Value 1 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'HomepageIsNewTabPage' -Value 0 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'NewTabPageSetFeedType' -Value 0 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'NewTabPageContentEnabled' -Value 0 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'NewTabPageQuickLinksEnabled' -Value 0 -Type DWord

    # Default search engine to DuckDuckGo
    Set-ItemProperty -Path $edgePolicyPath -Name 'DefaultSearchProviderEnabled' -Value 1 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'DefaultSearchProviderName' -Value 'DuckDuckGo' -Type String
    Set-ItemProperty -Path $edgePolicyPath -Name 'DefaultSearchProviderSearchURL' -Value 'https://duckduckgo.com/?q={searchTerms}' -Type String

    Write-LogMessage "Configured about:blank pages and DuckDuckGo search" -Level Success -Component 'EdgeHardening'

    # Disable Microsoft intrusive features
    Write-LogMessage "Disabling Microsoft tracking and bloat..." -Level Info -Component 'EdgeHardening'

    $disableFeatures = @{
        'PersonalizationReportingEnabled' = 0
        'SearchSuggestEnabled'            = 0
        'ShowMicrosoftRewards'            = 0
        'EdgeShoppingAssistantEnabled'    = 0
        'WebWidgetAllowed'                = 0
        'HubsSidebarEnabled'              = 0
        'EdgeCollectionsEnabled'          = 0
        'ConfigureDoNotTrack'             = 1
        'BlockThirdPartyCookies'          = 1
        'PasswordManagerEnabled'          = 0
        'AutofillAddressEnabled'          = 0
        'AutofillCreditCardEnabled'       = 0
        'SpellcheckEnabled'               = 0
        'TranslateEnabled'                = 0
        'ShowHomeButton'                  = 0
        'EdgeAssetDeliveryServiceEnabled' = 0
        'DiagnosticData'                  = 0
        'EdgeEnhanceImagesEnabled'        = 0
        'EfficiencyMode'                  = 0
    }

    foreach ($setting in $disableFeatures.GetEnumerator()) {
        Set-ItemProperty -Path $edgePolicyPath -Name $setting.Key -Value $setting.Value -Type DWord
    }

    Write-LogMessage "Disabled tracking, suggestions, and bloat features" -Level Success -Component 'EdgeHardening'

    # Additional privacy settings
    Set-ItemProperty -Path $edgePolicyPath -Name 'MetricsReportingEnabled' -Value 0 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'UserFeedbackAllowed' -Value 0 -Type DWord
    Set-ItemProperty -Path $edgePolicyPath -Name 'DefaultCookiesSetting' -Value 4 -Type DWord

    Write-LogMessage "Enhanced privacy settings applied" -Level Success -Component 'EdgeHardening'

    # Summary
    Write-Host ""
    Write-Host "Edge configuration complete!" -ForegroundColor Cyan
    Write-Host "  Start page: about:blank" -ForegroundColor White
    Write-Host "  New tabs: about:blank (MSN feed disabled)" -ForegroundColor White
    Write-Host "  Search: DuckDuckGo" -ForegroundColor White
    Write-Host "  Tracking: Disabled" -ForegroundColor White
    Write-Host "  Microsoft bloat: Removed" -ForegroundColor White
    Write-Host ""
    Write-Host "Restart Edge to apply all changes" -ForegroundColor Yellow
    Write-Host ""

    Write-LogMessage "Edge hardening complete" -Level Success -Component 'EdgeHardening'
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Set-EdgePrivacySettings'
)
