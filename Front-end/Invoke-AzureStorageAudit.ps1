<#
.SYNOPSIS
    Azure Storage Security Auditor met RSA Encryptie
    
.DESCRIPTION
    Scant alle Azure Storage Accounts in je tenant op security issues en stuurt 
    versleutelde data naar een Azure Function voor analyse.
    
.PARAMETER FunctionUrl
    De URL van je Azure Function endpoint
    
.PARAMETER PublicKeyPath
    Pad naar het RSA public key XML bestand (optioneel, anders wordt interactief gevraagd)
    
.PARAMETER OutputDirectory
    Directory waar lokale bestanden worden opgeslagen (optioneel)
    
.PARAMETER EnableComplianceCheck
    Schakel data residency compliance checking in (voor grote bedrijven)
    
.PARAMETER AllowedRegions
    Array van toegestane Azure regio's (alleen gebruikt met -EnableComplianceCheck)

.EXAMPLE
    .\Invoke-AzureStorageAudit.ps1 -FunctionUrl "https://yourfunction.azurewebsites.net/api/analyze"
    
.EXAMPLE
    .\Invoke-AzureStorageAudit.ps1 -FunctionUrl "https://..." -PublicKeyPath ".\rsa\public_key.xml"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FunctionUrl,
    
    [Parameter(Mandatory = $false)]
    [string]$PublicKeyPath = ".\rsa\public_key.xml",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableComplianceCheck,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AllowedRegions = @('westeurope', 'northeurope', 'germanywestcentral', 'francecentral', 'switzerlandnorth')
)

# ============================================================================
# CONFIGURATIE
# ============================================================================

# Security: Salt voor hashing (in productie opslaan in Azure Key Vault)
$script:HASH_SALT = if ($env:AUDIT_HASH_SALT) { $env:AUDIT_HASH_SALT } else { "default-audit-salt-2026" }

# Hardcoded RSA Public Key (voor oneliner usage)
$script:HARDCODED_PUBLIC_KEY = @"
<RSAKeyValue><Modulus>oRsbv50Sq9UvBaUFQU+hu1HvqHxkI2gO0RI7Zkt1nyW/MnqEzpp2Qp979+ggwF6GkJiCViwCh2mOWFWCBpa8NuMn1Z+w+3WXqX5YHrVftyeseA+CHkGI4Vn3BQBOaa1ValM0kd6gr0gCaEin/4XnoF8JGseCS/q/k7bvUFpJ5BIPOagXW2Sak6niMQpHclHTp5pF2PAKJEte3m46gh7ZZ85sh54R2pT7obdESTxd/5RUZkfzwatzXjg/jlvpl/WFq6RwhCGKXTDAYcgT5Iip+ZkpNnV21i/PKVasMYb8+C9O/xSnDEfZK00x8d4aPCMg619JRvFoH75cm8EnKsogsQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
"@

# ============================================================================
# HELPER FUNCTIES
# ============================================================================

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'Info' { 'Gray' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-AnonymizedIdentifier {
    <#
    .SYNOPSIS
        Anonymiseert gevoelige identifiers met SHA-256 hashing + salt
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$SensitiveValue,
        
        [Parameter(Mandatory = $false)]
        [string]$Prefix = ""
    )
    
    if ([string]::IsNullOrWhiteSpace($SensitiveValue)) {
        return "${Prefix}unknown"
    }
    
    try {
        $saltedValue = "$script:HASH_SALT$SensitiveValue"
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($saltedValue))
        $hashHex = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLower()
        $anonymized = $hashHex.Substring(0, 12)
        
        return if ($Prefix) { "${Prefix}${anonymized}" } else { $anonymized }
    }
    catch {
        Write-AuditLog "Anonymization error occurred (no sensitive data logged)" -Level Error
        return "${Prefix}error"
    }
}

function Get-PublicKeyXML {
    <#
    .SYNOPSIS
        Haalt de RSA public key op (hardcoded, uit bestand, of interactief)
    #>
    param(
        [string]$Path,
        [switch]$UseHardcoded
    )
    
    # Als UseHardcoded flag is gezet, gebruik hardcoded key
    if ($UseHardcoded) {
        Write-AuditLog "Using hardcoded public key" -Level Info
        return $script:HARDCODED_PUBLIC_KEY
    }
    
    # Probeer eerst het opgegeven pad
    if (![string]::IsNullOrWhiteSpace($Path) -and (Test-Path $Path)) {
        Write-AuditLog "Public key gevonden: $Path" -Level Info
        return Get-Content $Path -Raw
    }
    
    # Als geen path opgegeven of niet gevonden, gebruik hardcoded key als fallback
    if ([string]::IsNullOrWhiteSpace($Path) -or !(Test-Path $Path)) {
        Write-AuditLog "Using hardcoded public key (no file specified or not found)" -Level Info
        return $script:HARDCODED_PUBLIC_KEY
    }
    
    # Fallback: interactief vragen (alleen als er echt geen key beschikbaar is)
    Write-Host "`n" -NoNewline
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "🔑 RSA PUBLIC KEY CONFIGURATIE" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    $keyPath = Read-Host "Pad naar public_key.xml (of druk Enter voor hardcoded key)"
    
    if ([string]::IsNullOrWhiteSpace($keyPath)) {
        Write-AuditLog "Using hardcoded public key (user pressed Enter)" -Level Info
        return $script:HARDCODED_PUBLIC_KEY
    }
    else {
        # Van bestand
        if (Test-Path $keyPath) {
            return Get-Content $keyPath -Raw
        }
        else {
            throw "Public key bestand niet gevonden: $keyPath"
        }
    }
}

function Invoke-RSAEncryption {
    <#
    .SYNOPSIS
        Versleutelt data met RSA-2048 public key
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$PublicKeyXML
    )
    
    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($PublicKeyXML)
        
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        
        # RSA Encrypt met OAEP padding voor betere security
        $encryptedBytes = $rsa.Encrypt($dataBytes, $true)
        $base64Encrypted = [Convert]::ToBase64String($encryptedBytes)
        
        return $base64Encrypted
    }
    catch {
        Write-AuditLog "RSA encryptie gefaald: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        if ($rsa) {
            $rsa.Dispose()
        }
    }
}

function Get-OutputDirectory {
    <#
    .SYNOPSIS
        Vraagt gebruiker om output directory en valideert deze
    #>
    
    Write-Host "`n" -NoNewline
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "📁 OUTPUT DIRECTORY CONFIGURATIE" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    while ($true) {
        $userInput = Read-Host "Welke map dient dit te worden opgeslagen? (of druk Enter voor huidige map)"
        
        # Default naar huidige directory
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            $outputDir = Get-Location | Select-Object -ExpandProperty Path
            Write-Host "✅ Gebruik huidige map: $outputDir" -ForegroundColor Green
            return $outputDir
        }
        
        # Valideer pad
        try {
            $outputDir = [System.IO.Path]::GetFullPath($userInput)
            
            if (Test-Path $outputDir) {
                # Check of het een directory is
                if (-not (Test-Path $outputDir -PathType Container)) {
                    Write-Host "❌ Error: '$outputDir' is een bestand, geen map." -ForegroundColor Red
                    $retry = Read-Host "Probeer opnieuw? (j/n)"
                    if ($retry -ne 'j') { return $null }
                    continue
                }
                
                # Check schrijfrechten
                $testFile = Join-Path $outputDir ".write_test_$(Get-Random).tmp"
                try {
                    [System.IO.File]::WriteAllText($testFile, "test")
                    Remove-Item $testFile -Force
                    Write-Host "✅ Map gevonden en beschrijfbaar: $outputDir" -ForegroundColor Green
                    return $outputDir
                }
                catch {
                    Write-Host "❌ Error: Geen schrijfrechten voor '$outputDir'" -ForegroundColor Red
                    $retry = Read-Host "Probeer opnieuw? (j/n)"
                    if ($retry -ne 'j') { return $null }
                    continue
                }
            }
            else {
                # Directory bestaat niet - vraag om aan te maken
                Write-Host "⚠️ Map bestaat niet: $outputDir" -ForegroundColor Yellow
                $create = Read-Host "Wilt u deze map aanmaken? (j/n)"
                
                if ($create -eq 'j') {
                    try {
                        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
                        Write-Host "✅ Map aangemaakt: $outputDir" -ForegroundColor Green
                        Write-AuditLog "Created output directory: $outputDir" -Level Info
                        return $outputDir
                    }
                    catch {
                        Write-Host "❌ Error bij aanmaken map: $($_.Exception.Message)" -ForegroundColor Red
                        $retry = Read-Host "Probeer opnieuw? (j/n)"
                        if ($retry -ne 'j') { return $null }
                        continue
                    }
                }
                else {
                    $retry = Read-Host "Probeer een andere map? (j/n)"
                    if ($retry -ne 'j') { return $null }
                    continue
                }
            }
        }
        catch {
            Write-Host "❌ Ongeldige mapnaam: $($_.Exception.Message)" -ForegroundColor Red
            $retry = Read-Host "Probeer opnieuw? (j/n)"
            if ($retry -ne 'j') { return $null }
            continue
        }
    }
}

function Save-AIInputJSON {
    <#
    .SYNOPSIS
        Slaat geanonimiseerde findings op als JSON (veilig voor externe AI diensten)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Findings,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,
        
        [Parameter(Mandatory = $false)]
        [string]$FileName = "ai_input.json"
    )
    
    try {
        $filePath = Join-Path $OutputDirectory $FileName
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-AuditLog "AI input saved to $filePath ($($Findings.Count) findings)" -Level Success
        Write-Host "`n✅ AI input JSON saved: $filePath" -ForegroundColor Green
        Write-Host "   - $($Findings.Count) findings" -ForegroundColor Gray
        Write-Host "   - Safe to share with external AI services" -ForegroundColor Gray
    }
    catch {
        Write-AuditLog "Failed to save AI input JSON: $($_.Exception.Message)" -Level Error
        Write-Host "`n❌ Failed to save ${FileName}: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Save-LocalCorrelationMarkdown {
    <#
    .SYNOPSIS
        Maakt een Markdown tabel met correlatie tussen hashed en echte resource namen
        ⚠️ CONFIDENTIAL - Niet extern delen!
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Findings,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$ResourceMapping,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,
        
        [Parameter(Mandatory = $false)]
        [string]$FileName = "local_mapping.md"
    )
    
    try {
        $filePath = Join-Path $OutputDirectory $FileName
        $markdown = New-Object System.Text.StringBuilder
        
        [void]$markdown.AppendLine("# Local Resource Mapping")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("⚠️ **CONFIDENTIAL - DO NOT SHARE EXTERNALLY**")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("## Resource Correlation Table")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("| Hashed Name | Real Name | Subscription | Location | Issues |")
        [void]$markdown.AppendLine("|-------------|-----------|--------------|----------|--------|")
        
        foreach ($finding in $Findings) {
            $hashedName = $finding.resource_name_anonymized
            $realInfo = $ResourceMapping[$hashedName]
            
            if ($realInfo) {
                $realName = $realInfo.name
                $subscription = $realInfo.subscription
                $location = $finding.location
                $issues = ($finding.issues -join ', ') -replace '\|', '\|'
                
                [void]$markdown.AppendLine("| ``$hashedName`` | **$realName** | $subscription | $location | $issues |")
            }
        }
        
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("---")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("## Notes")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("- **Hashed Name**: Anonymized identifier used in AI analysis")
        [void]$markdown.AppendLine("- **Real Name**: Actual Azure resource name")
        [void]$markdown.AppendLine("- **Subscription**: Azure subscription containing the resource")
        [void]$markdown.AppendLine("- **Location**: Azure region where the resource is deployed")
        [void]$markdown.AppendLine("- **Issues**: Security issues found during audit")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("### Security Reminder")
        [void]$markdown.AppendLine("")
        [void]$markdown.AppendLine("This file maps anonymized identifiers back to real resource names.")
        [void]$markdown.AppendLine("Keep this file secure and never share it with external services.")
        
        $markdown.ToString() | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-AuditLog "Local correlation mapping saved to $filePath" -Level Success
        Write-Host "`n✅ Local correlation Markdown saved: $filePath" -ForegroundColor Green
        Write-Host "   - $($Findings.Count) resources mapped" -ForegroundColor Gray
        Write-Host "   - ⚠️ CONFIDENTIAL - Keep this file secure!" -ForegroundColor Yellow
    }
    catch {
        Write-AuditLog "Failed to save correlation markdown: $($_.Exception.Message)" -Level Error
        Write-Host "`n❌ Failed to save ${FileName}: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# HOOFDFUNCTIE: SECURITY AUDIT
# ============================================================================

function Invoke-AzureStorageSecurityAudit {
    <#
    .SYNOPSIS
        Voert security audit uit op alle Azure Storage Accounts in de tenant
    #>
    param(
        [Parameter(Mandatory = $false)]
        [bool]$EnableCompliance = $false,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRegions = @()
    )
    
    $findings = @()
    $resourceMapping = @{}
    
    Write-Host "`n" -NoNewline
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "🔍 AZURE STORAGE SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    # 1. Check Azure PowerShell module
    Write-AuditLog "Checking Azure PowerShell module..." -Level Info
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "❌ Az.Accounts module niet gevonden!" -ForegroundColor Red
        Write-Host "   Installeer met: Install-Module -Name Az -Scope CurrentUser" -ForegroundColor Yellow
        return $null
    }
    
    # 2. Check Azure context
    Write-AuditLog "Checking Azure authentication..." -Level Info
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "⚠️ Niet ingelogd bij Azure!" -ForegroundColor Yellow
        Write-Host "   Log in met: Connect-AzAccount" -ForegroundColor Yellow
        
        $login = Read-Host "Wilt u nu inloggen? (j/n)"
        if ($login -eq 'j') {
            Connect-AzAccount
            $context = Get-AzContext
            if (-not $context) {
                Write-Host "❌ Login mislukt!" -ForegroundColor Red
                return $null
            }
        }
        else {
            return $null
        }
    }
    
    Write-AuditLog "Authenticated as: $($context.Account.Id)" -Level Success
    
    # 3. Get alle subscriptions
    Write-AuditLog "Retrieving subscriptions..." -Level Info
    $subscriptions = Get-AzSubscription
    
    if (-not $subscriptions) {
        Write-Host "❌ Geen Azure subscriptions gevonden!" -ForegroundColor Red
        return $null
    }
    
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "🔍 TENANT-WIDE SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "Total Subscriptions: $($subscriptions.Count)" -ForegroundColor White
    
    if ($EnableCompliance -and $AllowedRegions.Count -gt 0) {
        Write-Host "Compliance Check: ✅ ENABLED" -ForegroundColor Green
        Write-Host "Allowed Regions: $($AllowedRegions -join ', ')" -ForegroundColor White
    }
    else {
        Write-Host "Compliance Check: ℹ️ DISABLED (location auditable only)" -ForegroundColor Gray
    }
    
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    # 4. Loop door alle subscriptions
    $totalAccountCount = 0
    $subIndex = 0
    
    foreach ($subscription in $subscriptions) {
        $subIndex++
        
        try {
            # Anonimiseer subscription info
            $anonymizedSubName = Get-AnonymizedIdentifier -SensitiveValue $subscription.Name -Prefix "sub_"
            $anonymizedSubId = Get-AnonymizedIdentifier -SensitiveValue $subscription.Id -Prefix "id_"
            
            # Store mapping
            $resourceMapping[$anonymizedSubId] = $subscription.Id
            $resourceMapping[$anonymizedSubName] = $subscription.Name
            
            Write-Host "[$subIndex/$($subscriptions.Count)] 📋 Subscription: $($subscription.Name)" -ForegroundColor White
            Write-Host "            Subscription ID: $($subscription.Id)" -ForegroundColor Gray
            Write-AuditLog "Auditing subscription $subIndex/$($subscriptions.Count): $($subscription.Name)" -Level Info
            
            # Set context naar deze subscription
            Set-AzContext -SubscriptionId $subscription.Id | Out-Null
            
        }
        catch {
            Write-AuditLog "Error processing subscription metadata (skipping): $($_.Exception.Message)" -Level Error
            continue
        }
        
        try {
            # 5. Scan storage accounts
            Write-AuditLog "Scanning storage accounts in subscription: $($subscription.Name)..." -Level Info
            $storageAccounts = Get-AzStorageAccount
            
            $accountCount = 0
            
            if (-not $storageAccounts) {
                Write-Host "  ℹ️ No storage accounts found in this subscription" -ForegroundColor Gray
                Write-AuditLog "No storage accounts found in subscription: $($subscription.Name)" -Level Warning
                continue
            }
            
            foreach ($account in $storageAccounts) {
                try {
                    $accountCount++
                    $totalAccountCount++
                    
                    # Security checks
                    $isPublic = $account.AllowBlobPublicAccess
                    $minTlsVersion = $account.MinimumTlsVersion
                    
                    # TLS compliance check
                    $isTlsCompliant = $true
                    if ($minTlsVersion) {
                        $isTlsCompliant = $minTlsVersion -in @('TLS1_2', 'TLS1_3')
                    }
                    else {
                        $isTlsCompliant = $false
                    }
                    
                    # Region compliance check (optioneel)
                    $isCompliantRegion = $true
                    if ($EnableCompliance -and $AllowedRegions.Count -gt 0) {
                        $isCompliantRegion = $account.Location.ToLower() -in ($AllowedRegions | ForEach-Object { $_.ToLower() })
                    }
                    
                    # Anonimiseer account name
                    $anonymizedAccountName = Get-AnonymizedIdentifier -SensitiveValue $account.StorageAccountName -Prefix "storage_"
                    
                    # Store mapping
                    $resourceMapping[$anonymizedAccountName] = @{
                        name            = $account.StorageAccountName
                        id              = $account.Id
                        location        = $account.Location
                        subscription    = $subscription.Name
                        min_tls_version = $minTlsVersion
                    }
                    
                    # Bepaal issues
                    $issues = @()
                    $severity = "Low"
                    
                    if ($isPublic) {
                        $issues += "Public Blob Access staat AAN"
                        $severity = "High"
                    }
                    
                    if (-not $isTlsCompliant) {
                        if ($minTlsVersion) {
                            $issues += "Minimum TLS Version te laag: $minTlsVersion (vereist: TLS1_2 of hoger)"
                        }
                        else {
                            $issues += "Minimum TLS Version niet ingesteld (vereist: TLS1_2 of hoger)"
                        }
                        $severity = "High"
                    }
                    
                    if ($EnableCompliance -and -not $isCompliantRegion) {
                        $issues += "Data Residency Violation - Region '$($account.Location)' niet toegestaan"
                        $severity = if ($severity -eq "High") { "Critical" } else { "High" }
                    }
                    
                    # Status
                    $status = if ($issues.Count -gt 0) { "⚠️ ONVEILIG" } else { "✅ VEILIG" }
                    
                    # Store finding (alleen als er issues zijn)
                    if ($issues.Count -gt 0) {
                        $finding = [PSCustomObject]@{
                            resource_name_anonymized     = $anonymizedAccountName
                            subscription_id_anonymized   = $anonymizedSubId
                            subscription_name_anonymized = $anonymizedSubName
                            type                         = "Storage Account"
                            issues                       = $issues
                            severity                     = $severity
                            location                     = $account.Location
                            min_tls_version              = $minTlsVersion
                            compliant_region             = if ($EnableCompliance) { $isCompliantRegion } else { $null }
                        }
                        $findings += $finding
                        Write-AuditLog "Security issue(s) found in $($account.StorageAccountName): $($issues -join ', ')" -Level Warning
                    }
                    
                    # Display locally
                    Write-Host "  [$status] $($account.StorageAccountName) (Location: $($account.Location))" -ForegroundColor $(if ($issues.Count -gt 0) { 'Yellow' } else { 'Green' })
                    foreach ($issue in $issues) {
                        Write-Host "           └─ ⚠️ $issue" -ForegroundColor Yellow
                    }
                    if ($issues.Count -gt 0) {
                        Write-Host "           └─ Resource ID: $($account.Id)" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-AuditLog "Error processing storage account (account skipped): $($_.Exception.Message)" -Level Error
                    continue
                }
            }
            
            Write-Host "  ✓ Scanned $accountCount storage account(s)" -ForegroundColor Green
            Write-AuditLog "Successfully scanned $accountCount storage account(s) in $($subscription.Name)" -Level Success
        }
        catch {
            Write-AuditLog "Azure API error while scanning subscription $($subscription.Name): $($_.Exception.Message)" -Level Error
            Write-Host "  ❌ Error scanning this subscription (API error)" -ForegroundColor Red
            continue
        }
    }
    
    # Return results
    return @{
        Findings          = $findings
        ResourceMapping   = $resourceMapping
        TotalAccountCount = $totalAccountCount
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    Write-Host "`n🛡️ [Catching Moles Security Auditor] 🛡️" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    # 1. Voer audit uit
    $auditResult = Invoke-AzureStorageSecurityAudit `
        -EnableCompliance $EnableComplianceCheck.IsPresent `
        -AllowedRegions $AllowedRegions
    
    if (-not $auditResult) {
        Write-Host "`n❌ Audit gefaald. Controleer de logs voor details." -ForegroundColor Red
        exit 1
    }
    
    $auditFindings = $auditResult.Findings
    $resourceMapping = $auditResult.ResourceMapping
    $totalAccounts = $auditResult.TotalAccountCount
    
    # 2. Toon samenvatting
    Write-Host "`n" -NoNewline
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host "--- AUDIT COMPLEET ---" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host "Total Storage Accounts Scanned: $totalAccounts" -ForegroundColor White
    Write-Host "Total Issues Found: $($auditFindings.Count)" -ForegroundColor White
    Write-Host "=" * 70 -ForegroundColor Green
    
    if ($auditFindings.Count -gt 0) {
        Write-Host "`n⚠️ $($auditFindings.Count) beveiligingsissue(s) gevonden!" -ForegroundColor Yellow
        Write-Host "`n📋 Kwetsbare Resources (LOKAAL - Niet delen):" -ForegroundColor Yellow
        Write-Host "-" * 60 -ForegroundColor Gray
        
        $idx = 1
        foreach ($finding in $auditFindings) {
            $anonName = $finding.resource_name_anonymized
            $realInfo = $resourceMapping[$anonName]
            
            if ($realInfo) {
                Write-Host "`n🔴 [$idx] $($realInfo.name)" -ForegroundColor Red
                Write-Host "   Subscription: $($realInfo.subscription)" -ForegroundColor Gray
                Write-Host "   Resource ID: $($realInfo.id)" -ForegroundColor Gray
                Write-Host "   Location: $($finding.location)" -ForegroundColor Gray
                Write-Host "   Minimum TLS Version: $(if ($realInfo.min_tls_version) { $realInfo.min_tls_version } else { 'Not Set' })" -ForegroundColor Gray
                if ($null -ne $finding.compliant_region) {
                    Write-Host "   Compliant Region: $(if ($finding.compliant_region) { '✅ Yes' } else { '❌ No' })" -ForegroundColor Gray
                }
                Write-Host "   Issues: $($finding.issues -join ', ')" -ForegroundColor Yellow
                Write-Host "   Severity: $($finding.severity)" -ForegroundColor $(if ($finding.severity -eq 'Critical') { 'Red' } elseif ($finding.severity -eq 'High') { 'Yellow' } else { 'Gray' })
                $idx++
            }
        }
    }
    else {
        Write-Host "`n✅ Geen kritieke beveiligingsissues gevonden." -ForegroundColor Green
    }
    
    # 3. Sla bestanden op (optioneel)
    if (-not $OutputDirectory) {
        $OutputDirectory = Get-OutputDirectory
    }
    
    if ($OutputDirectory) {
        Write-Host "`n" -NoNewline
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "💾 SAVING FILES..." -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan
        
        Save-AIInputJSON -Findings $auditFindings -OutputDirectory $OutputDirectory -FileName "ai_input.json"
        Save-LocalCorrelationMarkdown -Findings $auditFindings -ResourceMapping $resourceMapping -OutputDirectory $OutputDirectory -FileName "local_mapping.md"
        
        Write-Host "`n" -NoNewline
        Write-Host "=" * 70 -ForegroundColor Green
        Write-Host "✅ All files saved successfully!" -ForegroundColor Green
        Write-Host "=" * 70 -ForegroundColor Green
    }
    
    # 4. RSA Encryptie en verzenden naar Function App (optioneel)
    if ($auditFindings.Count -gt 0) {
        Write-Host "`n" -NoNewline
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "🔐 VERSLEUTELDE DATA VERZENDEN" -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host ""
        
        if (-not $FunctionUrl) {
            $sendToFunction = Read-Host "Wilt u versleutelde data naar Azure Function sturen? (j/n)"
            if ($sendToFunction -eq 'j') {
                $FunctionUrl = Read-Host "Function App URL"
            }
        }
        
        if ($FunctionUrl) {
            Write-Host "`n[1/3] Public key laden..." -ForegroundColor Gray
            try {
                $publicKeyXML = Get-PublicKeyXML -Path $PublicKeyPath
                Write-AuditLog "Public key loaded successfully" -Level Success
            }
            catch {
                Write-Host "❌ Fout bij laden public key: $($_.Exception.Message)" -ForegroundColor Red
                Write-AuditLog "Failed to load public key: $($_.Exception.Message)" -Level Error
                exit 1
            }
            
            Write-Host "[2/3] Data versleutelen met RSA-2048..." -ForegroundColor Gray
            try {
                $payload = $auditFindings | ConvertTo-Json -Compress -Depth 10
                $encryptedData = Invoke-RSAEncryption -Data $payload -PublicKeyXML $publicKeyXML
                Write-AuditLog "Data encrypted successfully ($($payload.Length) bytes -> $($encryptedData.Length) bytes)" -Level Success
            }
            catch {
                Write-Host "❌ Fout bij encryptie: $($_.Exception.Message)" -ForegroundColor Red
                Write-AuditLog "Encryption failed: $($_.Exception.Message)" -Level Error
                exit 1
            }
            
            Write-Host "[3/3] Versleutelde data verzenden naar analyse-engine..." -ForegroundColor Gray
            try {
                $response = Invoke-RestMethod -Uri $FunctionUrl -Method Post -Body $encryptedData -ContentType "application/octet-stream"
                Write-Host "`n✅ $response" -ForegroundColor Green
                Write-AuditLog "Data successfully sent to Function App" -Level Success
            }
            catch {
                Write-Host "`n❌ Fout bij verzenden: $($_.Exception.Message)" -ForegroundColor Red
                Write-AuditLog "Failed to send data to Function App: $($_.Exception.Message)" -Level Error
            }
        }
    }
    
    Write-Host "`n✅ Audit voltooid!" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "`n❌ Onverwachte fout tijdens audit." -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-AuditLog "Critical error in main execution: $($_.Exception.Message)" -Level Error
    exit 1
}
