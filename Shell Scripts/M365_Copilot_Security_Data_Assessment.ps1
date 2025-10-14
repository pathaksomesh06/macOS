# M365 Copilot Security Assessment - Enhanced Edition

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Global variables
$script:assessmentResults = @()
$script:tenantId = $null

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "M365 Copilot Security Assessment - Enhanced Edition"
$form.Size = New-Object System.Drawing.Size(1100, 700)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# Create TabControl
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(1070, 640)
$tabControl.Font = New-Object System.Drawing.Font("Segoe UI", 10)

# Tab 1: Authentication
$tabAuth = New-Object System.Windows.Forms.TabPage
$tabAuth.Text = "1. Connect"
$tabAuth.BackColor = [System.Drawing.Color]::White

$lblTenant = New-Object System.Windows.Forms.Label
$lblTenant.Text = "Azure AD Tenant ID:"
$lblTenant.Location = New-Object System.Drawing.Point(50, 50)
$lblTenant.Size = New-Object System.Drawing.Size(200, 25)

$txtTenant = New-Object System.Windows.Forms.TextBox
$txtTenant.Location = New-Object System.Drawing.Point(50, 80)
$txtTenant.Size = New-Object System.Drawing.Size(400, 30)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "Connect to Microsoft 365"
$btnConnect.Location = New-Object System.Drawing.Point(50, 120)
$btnConnect.Size = New-Object System.Drawing.Size(200, 40)
$btnConnect.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnConnect.ForeColor = [System.Drawing.Color]::White
$btnConnect.FlatStyle = "Flat"

$lblAuthStatus = New-Object System.Windows.Forms.Label
$lblAuthStatus.Text = "Status: Not connected"
$lblAuthStatus.Location = New-Object System.Drawing.Point(50, 180)
$lblAuthStatus.Size = New-Object System.Drawing.Size(600, 25)
$lblAuthStatus.ForeColor = [System.Drawing.Color]::Gray

$tabAuth.Controls.AddRange(@($lblTenant, $txtTenant, $btnConnect, $lblAuthStatus))

# Tab 2: Run Assessment
$tabRun = New-Object System.Windows.Forms.TabPage
$tabRun.Text = "2. Run Assessment"
$tabRun.BackColor = [System.Drawing.Color]::White

$btnRunAssessment = New-Object System.Windows.Forms.Button
$btnRunAssessment.Text = "Start Full Assessment"
$btnRunAssessment.Location = New-Object System.Drawing.Point(400, 50)
$btnRunAssessment.Size = New-Object System.Drawing.Size(250, 50)
$btnRunAssessment.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
$btnRunAssessment.ForeColor = [System.Drawing.Color]::White
$btnRunAssessment.FlatStyle = "Flat"
$btnRunAssessment.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(50, 150)
$progressBar.Size = New-Object System.Drawing.Size(960, 30)
$progressBar.Style = "Continuous"

$txtProgress = New-Object System.Windows.Forms.TextBox
$txtProgress.Location = New-Object System.Drawing.Point(50, 200)
$txtProgress.Size = New-Object System.Drawing.Size(960, 350)
$txtProgress.Multiline = $true
$txtProgress.ScrollBars = "Vertical"
$txtProgress.ReadOnly = $true
$txtProgress.Font = New-Object System.Drawing.Font("Consolas", 9)

$tabRun.Controls.AddRange(@($btnRunAssessment, $progressBar, $txtProgress))

# Tab 3: Detailed Assessment
$tabDetailed = New-Object System.Windows.Forms.TabPage
$tabDetailed.Text = "3. Detailed Assessment"
$tabDetailed.BackColor = [System.Drawing.Color]::White

$lblDetailedInfo = New-Object System.Windows.Forms.Label
$lblDetailedInfo.Text = "Enhanced Assessment Modules:"
$lblDetailedInfo.Location = New-Object System.Drawing.Point(50, 30)
$lblDetailedInfo.Size = New-Object System.Drawing.Size(400, 25)
$lblDetailedInfo.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)

$lblModules = New-Object System.Windows.Forms.Label
$lblModules.Text = @"
✓ Unified Groups Analysis (Teams, Viva Engage, Outlook Groups)
✓ Retention Policies Assessment
✓ Azure Information Protection (AIP) Status
✓ Sensitivity Labels with File Protection
✓ Enhanced Data Classification
✓ DLP Policies Verification
✓ License Readiness Check
✓ Inactive Content Detection
"@
$lblModules.Location = New-Object System.Drawing.Point(50, 70)
$lblModules.Size = New-Object System.Drawing.Size(800, 200)
$lblModules.Font = New-Object System.Drawing.Font("Segoe UI", 10)

$lblBenefits = New-Object System.Windows.Forms.Label
$lblBenefits.Text = @"
Benefits of Enhanced Assessment:
• Comprehensive Copilot security posture evaluation
• Detailed data classification and protection analysis
• Retention policy compliance verification
• AIP service configuration validation
• Teams and collaboration security assessment
• Actionable recommendations with severity ratings
"@
$lblBenefits.Location = New-Object System.Drawing.Point(50, 300)
$lblBenefits.Size = New-Object System.Drawing.Size(800, 150)
$lblBenefits.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$lblBenefits.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)

$tabDetailed.Controls.AddRange(@($lblDetailedInfo, $lblModules, $lblBenefits))

# Tab 4: Results
$tabResults = New-Object System.Windows.Forms.TabPage
$tabResults.Text = "4. Results"
$tabResults.BackColor = [System.Drawing.Color]::White

$dgvResults = New-Object System.Windows.Forms.DataGridView
$dgvResults.Location = New-Object System.Drawing.Point(20, 20)
$dgvResults.Size = New-Object System.Drawing.Size(1020, 500)
$dgvResults.AutoSizeColumnsMode = "Fill"
$dgvResults.AllowUserToAddRows = $false
$dgvResults.ReadOnly = $true
$dgvResults.SelectionMode = "FullRowSelect"
$dgvResults.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$dgvResults.Columns.Add("ID", "ID")
$dgvResults.Columns["ID"].Width = 50
$dgvResults.Columns.Add("Finding", "Finding")
$dgvResults.Columns["Finding"].Width = 250
$dgvResults.Columns.Add("Issue", "Issue & Copilot Impact")
$dgvResults.Columns["Issue"].Width = 400
$dgvResults.Columns.Add("Severity", "Severity")
$dgvResults.Columns["Severity"].Width = 100
$dgvResults.Columns.Add("Probability", "Probability")
$dgvResults.Columns["Probability"].Width = 100
$dgvResults.Columns.Add("Details", "Data Details")
$dgvResults.Columns["Details"].Width = 200

$btnExportCSV = New-Object System.Windows.Forms.Button
$btnExportCSV.Text = "Export to CSV"
$btnExportCSV.Location = New-Object System.Drawing.Point(20, 540)
$btnExportCSV.Size = New-Object System.Drawing.Size(150, 35)
$btnExportCSV.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnExportCSV.ForeColor = [System.Drawing.Color]::White
$btnExportCSV.FlatStyle = "Flat"

$btnExportHTML = New-Object System.Windows.Forms.Button
$btnExportHTML.Text = "Generate HTML Report"
$btnExportHTML.Location = New-Object System.Drawing.Point(190, 540)
$btnExportHTML.Size = New-Object System.Drawing.Size(180, 35)
$btnExportHTML.BackColor = [System.Drawing.Color]::FromArgb(255, 185, 0)
$btnExportHTML.ForeColor = [System.Drawing.Color]::White
$btnExportHTML.FlatStyle = "Flat"

$tabResults.Controls.AddRange(@($dgvResults, $btnExportCSV, $btnExportHTML))

$tabControl.TabPages.AddRange(@($tabAuth, $tabRun, $tabDetailed, $tabResults))
$form.Controls.Add($tabControl)

# Event Handlers
$btnConnect.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtTenant.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a Tenant ID", "Missing Information", "OK", "Warning")
        return
    }
    
    $lblAuthStatus.Text = "Status: Connecting..."
    $lblAuthStatus.ForeColor = [System.Drawing.Color]::Orange
    $btnConnect.Enabled = $false
    
    try {
        $requiredModules = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users',
            'Microsoft.Graph.Groups',
            'Microsoft.Graph.Sites',
            'Microsoft.Graph.Reports',
            'ExchangeOnlineManagement',
            'AIPService'
        )
        
        foreach ($module in $requiredModules) {
            if (!(Get-Module -ListAvailable -Name $module)) {
                $lblAuthStatus.Text = "Installing $module..."
                [System.Windows.Forms.Application]::DoEvents()
                Install-Module $module -Scope CurrentUser -Force -AllowClobber
            }
            Import-Module $module -ErrorAction Stop
        }
        
        $script:tenantId = $txtTenant.Text.Trim()
        
        Connect-MgGraph -TenantId $script:tenantId -Scopes @(
            "Directory.Read.All",
            "Group.Read.All",
            "User.Read.All",
            "Sites.Read.All",
            "Reports.Read.All"
        )
        
        $context = Get-MgContext
        if ($context) {
            $script:tenantId = $context.TenantId
            $lblAuthStatus.Text = "Status: Connected to $($context.TenantId)"
            $lblAuthStatus.ForeColor = [System.Drawing.Color]::Green
            $tabControl.SelectedIndex = 1
        }
    }
    catch {
        $lblAuthStatus.Text = "Status: Failed - $($_.Exception.Message)"
        $lblAuthStatus.ForeColor = [System.Drawing.Color]::Red
    }
    finally {
        $btnConnect.Enabled = $true
    }
})

$btnRunAssessment.Add_Click({
    $context = Get-MgContext
    if (-not $context) {
        [System.Windows.Forms.MessageBox]::Show("Please connect first", "Not Connected", "OK", "Warning")
        $tabControl.SelectedIndex = 0
        return
    }
    
    $btnRunAssessment.Enabled = $false
    $progressBar.Value = 0
    $txtProgress.Clear()
    $script:assessmentResults = @()
    $findingID = 1
    
    function Update-Progress($message, $percent) {
        $txtProgress.AppendText("$(Get-Date -Format 'HH:mm:ss') - $message`r`n")
        $progressBar.Value = $percent
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    try {
        Update-Progress "Starting assessment..." 5
        
        # 1. USERS ASSESSMENT
        Update-Progress "Checking users..." 10
        try {
            $users = Get-MgUser -All -Property UserType,AccountEnabled,CreatedDateTime,AssignedLicenses
            $totalUsers = $users.Count
            $guestUsers = ($users | Where-Object { $_.UserType -eq 'Guest' }).Count
            $memberUsers = $totalUsers - $guestUsers
            $disabledUsers = ($users | Where-Object { $_.AccountEnabled -eq $false }).Count
            $licensedUsers = ($users | Where-Object { $_.AssignedLicenses.Count -gt 0 }).Count
            
            Update-Progress "  Found $totalUsers total users" 12
            Update-Progress "  Members: $memberUsers, Guests: $guestUsers" 14
            Update-Progress "  Licensed: $licensedUsers, Disabled: $disabledUsers" 15
            
            if ($guestUsers -gt 0) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Access: Guest users present"
                    Issue = "$guestUsers guest users have access to tenant. Review their permissions for Copilot-indexed content"
                    Severity = if ($guestUsers -gt 50) { "High" } else { "Medium" }
                    Probability = "High"
                    Details = "Guests: $guestUsers/$totalUsers ($('{0:P0}' -f ($guestUsers/$totalUsers)))"
                }
            }
            
            if ($disabledUsers -gt 20) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Lifecycle: Excessive disabled accounts"
                    Issue = "$disabledUsers disabled accounts still present. Clean up to reduce attack surface"
                    Severity = "Low"
                    Probability = "Medium"
                    Details = "Disabled: $disabledUsers accounts"
                }
            }
        }
        catch {
            Update-Progress "  Error checking users: $($_.Exception.Message)" 15
        }
        
        # 2. UNIFIED GROUPS DETAILED ASSESSMENT
        Update-Progress "Checking M365 Groups..." 20
        try {
            $groups = Get-MgGroup -All -Property Visibility,CreatedDateTime,MembershipRule,GroupTypes,AssignedLabels,ResourceBehaviorOptions,ResourceProvisioningOptions
            $totalGroups = $groups.Count
            $m365Groups = ($groups | Where-Object { $_.GroupTypes -contains "Unified" }).Count
            $publicGroups = ($groups | Where-Object { $_.Visibility -eq 'Public' }).Count
            $privateGroups = ($groups | Where-Object { $_.Visibility -eq 'Private' }).Count
            $dynamicGroups = ($groups | Where-Object { $_.MembershipRule -ne $null }).Count
            
            Update-Progress "  Found $totalGroups total groups" 22
            Update-Progress "  M365 Groups: $m365Groups" 24
            Update-Progress "  Public: $publicGroups, Private: $privateGroups, Dynamic: $dynamicGroups" 25
            
            # Enhanced Unified Groups Analysis
            $unifiedGroups = $groups | Where-Object { $_.GroupTypes -contains "Unified" }
            $teamsEnabled = ($unifiedGroups | Where-Object { $_.ResourceProvisioningOptions -contains 'Team' }).Count
            $vivaEngageEnabled = ($unifiedGroups | Where-Object { 
                $_.ResourceProvisioningOptions -contains 'Yammer' -or 
                $_.CreationOptions -contains 'YammerProvisioning' 
            }).Count
            $outlookGroups = $m365Groups - $teamsEnabled - $vivaEngageEnabled
            
            Update-Progress "  Teams: $teamsEnabled, Viva Engage: $vivaEngageEnabled, Outlook: $outlookGroups" 26
            
            # Check for groups with sensitivity labels
            $labeledGroups = ($unifiedGroups | Where-Object { $_.AssignedLabels.Count -gt 0 }).Count
            $unlabeledGroups = $m365Groups - $labeledGroups
            
            if ($unlabeledGroups -gt 0) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Classification: Unlabeled Unified Groups"
                    Issue = "$unlabeledGroups of $m365Groups Unified Groups lack sensitivity labels. Copilot may access unclassified data"
                    Severity = if ($unlabeledGroups -gt ($m365Groups * 0.7)) { "High" } else { "Medium" }
                    Probability = "High"
                    Details = "Unlabeled: $unlabeledGroups/$m365Groups groups"
                }
            }
            
            if ($publicGroups -gt 10) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Access: Excessive public M365 Groups"
                    Issue = "$publicGroups public groups allow all users to access content. Copilot indexes all public group data"
                    Severity = if ($publicGroups -gt 50) { "Critical" } else { "High" }
                    Probability = "High"
                    Details = "Public: $publicGroups/$m365Groups M365 groups"
                }
            }
            
            # Check for Teams-specific risks
            if ($teamsEnabled -gt 0) {
                $publicTeams = ($unifiedGroups | Where-Object { 
                    $_.ResourceProvisioningOptions -contains 'Team' -and $_.Visibility -eq 'Public' 
                }).Count
                
                if ($publicTeams -gt 5) {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Access: Public Teams channels"
                        Issue = "$publicTeams public Teams detected. All channel content accessible to Copilot"
                        Severity = "High"
                        Probability = "High"
                        Details = "Public Teams: $publicTeams/$teamsEnabled"
                    }
                }
            }
            
            # Check orphaned groups
            $orphanedGroups = 0
            $sampledGroups = $unifiedGroups | Select-Object -First 30
            foreach ($group in $sampledGroups) {
                try {
                    $owners = Get-MgGroupOwner -GroupId $group.Id -ErrorAction SilentlyContinue
                    if ($owners.Count -eq 0) {
                        $orphanedGroups++
                    }
                }
                catch {
                    # Skip
                }
            }
            
            if ($orphanedGroups -gt 0) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Access: Orphaned M365 Groups"
                    Issue = "Found $orphanedGroups groups without owners in sample. Unmanaged groups pose security risk"
                    Severity = "Medium"
                    Probability = "High"
                    Details = "Orphaned: $orphanedGroups/30 sampled"
                }
            }
        }
        catch {
            Update-Progress "  Error checking groups: $($_.Exception.Message)" 25
        }
        
        # 3. SHAREPOINT SITES 
        Update-Progress "Checking SharePoint sites..." 30
        try {
            $sites = Get-MgSite -Search "*" -Property DisplayName,CreatedDateTime,WebUrl -ErrorAction Stop
            $siteCount = $sites.Count
            
            Update-Progress "  Found $siteCount SharePoint sites" 35
            
            if ($siteCount -gt 0) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Access: SharePoint sites active"
                    Issue = "$siteCount SharePoint sites detected. Review external sharing settings for Copilot data exposure"
                    Severity = "Medium"
                    Probability = "Medium"
                    Details = "Sites: $siteCount"
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*SPO license*") {
                Update-Progress "  No SharePoint Online license detected - skipping site checks" 35
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "License: No SharePoint Online"
                    Issue = "Tenant lacks SPO license. SharePoint assessment skipped"
                    Severity = "Low"
                    Probability = "Low"
                    Details = "SPO not licensed"
                }
            }
            else {
                Update-Progress "  Error checking sites: $($_.Exception.Message)" 35
            }
        }
        
        # 4. RETENTION POLICIES ASSESSMENT
        Update-Progress "Checking retention policies..." 40
        try {
            # Connect to Exchange Online and Compliance Center
            Connect-ExchangeOnline -ErrorAction SilentlyContinue
            Connect-IPPSSession -ErrorAction SilentlyContinue
            
            # Get organization configuration for InPlaceHolds
            $orgConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
            $retentionPolicies = @()
            
            if ($orgConfig -and $orgConfig.InPlaceHolds) {
                Update-Progress "  Found $($orgConfig.InPlaceHolds.Count) retention policies" 42
                
                foreach ($inPlaceHold in $orgConfig.InPlaceHolds) {
                    try {
                        $holdGuid = [System.GUID]::Parse($inPlaceHold.SubString(3).Split(':')[0])
                        $policy = $null
                        
                        # Try to get retention compliance policy
                        try {
                            $policy = Get-RetentionCompliancePolicy $holdGuid -ErrorAction Stop
                        }
                        catch {
                            # Try app retention policy
                            $policy = Get-AppRetentionCompliancePolicy $holdGuid -ErrorAction Stop
                        }
                        
                        if ($policy) {
                            $retentionPolicies += [PSCustomObject]@{
                                Name = $policy.Name
                                Created = $policy.WhenCreatedUTC
                                Updated = $policy.WhenChangedUTC
                                InPlaceHold = $inPlaceHold
                            }
                        }
                    }
                    catch {
                        # Skip problematic policies
                    }
                }
                
                if ($retentionPolicies.Count -eq 0) {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Lifecycle: No active retention policies"
                        Issue = "No retention policies found. Copilot may access data that should be deleted"
                        Severity = "High"
                        Probability = "High"
                        Details = "Retention policies: 0"
                    }
                }
                elseif ($retentionPolicies.Count -lt 3) {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Lifecycle: Limited retention policies"
                        Issue = "Only $($retentionPolicies.Count) retention policies configured. May not cover all data types"
                        Severity = "Medium"
                        Probability = "Medium"
                        Details = "Retention policies: $($retentionPolicies.Count)"
                    }
                }
                else {
                    Update-Progress "  $($retentionPolicies.Count) retention policies configured - adequate" 45
                }
            }
            else {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Lifecycle: Retention policy status unknown"
                    Issue = "Cannot access retention policy configuration. Manual review required"
                    Severity = "Medium"
                    Probability = "Medium"
                    Details = "Access denied or not configured"
                }
            }
        }
        catch {
            Update-Progress "  Error checking retention policies: $($_.Exception.Message)" 45
            $script:assessmentResults += [PSCustomObject]@{
                ID = $findingID++
                Finding = "Data Lifecycle: Retention policy check failed"
                Issue = "Unable to verify retention policies. Manual review required"
                Severity = "Medium"
                Probability = "Medium"
                Details = "Error: $($_.Exception.Message)"
            }
        }
        
        # 5. AZURE INFORMATION PROTECTION (AIP) ASSESSMENT
        Update-Progress "Checking Azure Information Protection..." 50
        try {
            # Connect to AIP Service
            Connect-AipService -ErrorAction SilentlyContinue
            
            $aipStatus = Get-AipService -ErrorAction SilentlyContinue
            $aipOnboarding = Get-AipServiceOnboardingControlPolicy -ErrorAction SilentlyContinue
            
            if ($aipStatus -eq "Enabled") {
                Update-Progress "  AIP Service is enabled" 52
                
                if ($aipOnboarding.Scope -eq "All") {
                    Update-Progress "  AIP enabled for all users" 54
                    $rmsLicenseRequired = $aipOnboarding.UseRmsUserLicense
                    
                    if ($rmsLicenseRequired) {
                        $script:assessmentResults += [PSCustomObject]@{
                            ID = $findingID++
                            Finding = "Data Protection: AIP RMS license required"
                            Issue = "AIP enabled but RMS license required for protection. Users may not be able to protect content"
                            Severity = "Medium"
                            Probability = "Medium"
                            Details = "AIP: Enabled, RMS License: Required"
                        }
                    }
                    else {
                        Update-Progress "  AIP properly configured for all users without license requirement" 55
                    }
                }
                else {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Protection: AIP scoped to limited users"
                        Issue = "AIP enabled but scoped to group $($aipOnboarding.SecurityGroupObjectId). Not all users can protect content"
                        Severity = "High"
                        Probability = "High"
                        Details = "AIP: Scoped to group $($aipOnboarding.SecurityGroupObjectId)"
                    }
                }
            }
            else {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Protection: AIP Service disabled"
                    Issue = "Azure Information Protection is disabled. Users cannot protect sensitive documents"
                    Severity = "Critical"
                    Probability = "High"
                    Details = "AIP: Disabled"
                }
            }
            
            # Disconnect AIP
            Disconnect-AipService -ErrorAction SilentlyContinue
        }
        catch {
            Update-Progress "  Error checking AIP: $($_.Exception.Message)" 55
            $script:assessmentResults += [PSCustomObject]@{
                ID = $findingID++
                Finding = "Data Protection: AIP status unknown"
                Issue = "Cannot verify Azure Information Protection status. Manual review required"
                Severity = "Medium"
                Probability = "Medium"
                Details = "AIP check failed: $($_.Exception.Message)"
            }
        }
        
        # 6. SENSITIVITY LABELS DETAILED ASSESSMENT
        Update-Progress "Checking sensitivity labels..." 60
        try {
            # Try to get labels via Exchange Online PowerShell
            $labels = Get-Label -ErrorAction SilentlyContinue
            $labelCount = if ($labels) { $labels.Count } else { 0 }
            
            if ($labelCount -eq 0) {
                # Fallback to Graph API
                $graphLabels = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels" -ErrorAction SilentlyContinue
                $labelCount = if ($graphLabels.value) { $graphLabels.value.Count } else { 0 }
            }
            
            Update-Progress "  Found $labelCount sensitivity labels" 62
            
            if ($labelCount -eq 0) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Security: No sensitivity labels"
                    Issue = "Zero sensitivity labels configured. Copilot will access all data without classification controls"
                    Severity = "Critical"
                    Probability = "High"
                    Details = "Labels: 0"
                }
            }
            elseif ($labelCount -lt 5) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Security: Insufficient sensitivity labels"
                    Issue = "Only $labelCount labels configured. Insufficient for comprehensive data classification"
                    Severity = "High"
                    Probability = "Medium"
                    Details = "Labels: $labelCount"
                }
            }
            else {
                # Check for file protection labels
                $fileLabelsCount = 0
                if ($labels) {
                    $fileLabelsCount = ($labels | Where-Object { $_.ContentType -match "File" }).Count
                }
                
                if ($fileLabelsCount -eq 0) {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Security: No file protection labels"
                        Issue = "No sensitivity labels have file protection enabled. Documents cannot be automatically protected"
                        Severity = "High"
                        Probability = "High"
                        Details = "File protection labels: 0/$labelCount"
                    }
                }
                else {
                    Update-Progress "  $labelCount labels configured ($fileLabelsCount with file protection) - adequate" 65
                }
            }
        }
        catch {
            $script:assessmentResults += [PSCustomObject]@{
                ID = $findingID++
                Finding = "Data Security: Unable to verify labels"
                Issue = "Cannot access sensitivity label configuration. Manual review required"
                Severity = "Medium"
                Probability = "Medium"
                Details = "Access denied or not configured"
            }
        }
        
        # 7. INACTIVE CONTENT
        Update-Progress "Checking for inactive content..." 70
        try {
            $ninetyDaysAgo = (Get-Date).AddDays(-90)
            $yearAgo = (Get-Date).AddDays(-365)
            
            if ($groups) {
                $oldGroups = ($groups | Where-Object { $_.CreatedDateTime -lt $ninetyDaysAgo }).Count
                $veryOldGroups = ($groups | Where-Object { $_.CreatedDateTime -lt $yearAgo }).Count
                
                if ($oldGroups -gt 20) {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Lifecycle: Aging groups detected"
                        Issue = "$oldGroups groups created 90+ days ago ($veryOldGroups over 1 year). Review for obsolete content"
                        Severity = "Low"
                        Probability = "High"
                        Details = "Old: $oldGroups (>90d), $veryOldGroups (>365d)"
                    }
                }
            }
            
            if ($users) {
                $inactiveUsers = ($users | Where-Object { 
                    $_.AccountEnabled -eq $true -and 
                    $_.CreatedDateTime -lt $ninetyDaysAgo 
                }).Count
                
                if ($inactiveUsers -gt 50) {
                    $script:assessmentResults += [PSCustomObject]@{
                        ID = $findingID++
                        Finding = "Data Lifecycle: Potentially inactive users"
                        Issue = "$inactiveUsers active accounts created 90+ days ago. Review for actual usage"
                        Severity = "Low"
                        Probability = "Medium"
                        Details = "Potentially inactive: $inactiveUsers"
                    }
                }
            }
        }
        catch {
            Update-Progress "  Error checking inactive content: $($_.Exception.Message)" 72
        }
        
        # 8. DLP POLICIES
        Update-Progress "Checking DLP policies..." 75
        try {
            $dlpPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/informationProtection/policy/labels" -ErrorAction SilentlyContinue
            $dlpCount = if ($dlpPolicies.value) { $dlpPolicies.value.Count } else { 0 }
            
            if ($dlpCount -lt 3) {
                $script:assessmentResults += [PSCustomObject]@{
                    ID = $findingID++
                    Finding = "Data Security: Limited DLP policies"
                    Issue = "Only $dlpCount DLP-related policies found. Copilot may expose sensitive data without controls"
                    Severity = "High"
                    Probability = "Medium"
                    Details = "DLP policies: $dlpCount"
                }
            }
        }
        catch {
            Update-Progress "  Unable to check DLP policies" 75
        }
        
        # 9. LICENSE READINESS
        Update-Progress "Checking license readiness..." 80
        if ($licensedUsers) {
            $licenseRatio = $licensedUsers / $totalUsers
            $script:assessmentResults += [PSCustomObject]@{
                ID = $findingID++
                Finding = "Copilot Readiness: License coverage"
                Issue = "$licensedUsers of $totalUsers users licensed ($('{0:P0}' -f $licenseRatio)). Verify Copilot license requirements"
                Severity = if ($licenseRatio -lt 0.5) { "High" } else { "Medium" }
                Probability = "Medium"
                Details = "Licensed: $licensedUsers/$totalUsers"
            }
        }
        
        # 10. GENERAL RECOMMENDATIONS
        Update-Progress "Adding governance recommendations..." 90
        
        $script:assessmentResults += [PSCustomObject]@{
            ID = $findingID++
            Finding = "Gen AI Policy: No governance framework"
            Issue = "No automated AI governance detection. Establish formal Generative AI usage guidelines"
            Severity = "Critical"
            Probability = "High"
            Details = "Manual policy review required"
        }
        
        $script:assessmentResults += [PSCustomObject]@{
            ID = $findingID++
            Finding = "Data Lifecycle: Retention policies"
            Issue = "Retention policy status unknown. Implement policies to prevent Copilot accessing obsolete data"
            Severity = "Medium"
            Probability = "Medium"
            Details = "Manual verification needed"
        }
        
        $script:assessmentResults += [PSCustomObject]@{
            ID = $findingID++
            Finding = "Viva Insights: Privacy review needed"
            Issue = "Viva Insights configuration not verified. Review privacy settings for Copilot data exposure"
            Severity = "Low"
            Probability = "Low"
            Details = "Manual check required"
        }
        
        Update-Progress "Assessment completed!" 100
        Update-Progress "Total findings: $($script:assessmentResults.Count)" 100
        
        # Populate DataGridView
        $dgvResults.Rows.Clear()
        foreach ($result in $script:assessmentResults) {
            $rowIndex = $dgvResults.Rows.Add()
            $row = $dgvResults.Rows[$rowIndex]
            $row.Cells["ID"].Value = $result.ID
            $row.Cells["Finding"].Value = $result.Finding
            $row.Cells["Issue"].Value = $result.Issue
            $row.Cells["Severity"].Value = $result.Severity
            $row.Cells["Probability"].Value = $result.Probability
            $row.Cells["Details"].Value = $result.Details
            
            switch ($result.Severity) {
                "Critical" { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 230) }
                "High" { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 245, 230) }
                "Medium" { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 230) }
                "Low" { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(230, 255, 230) }
            }
        }
        
        [System.Windows.Forms.MessageBox]::Show("Enhanced Assessment completed with $($script:assessmentResults.Count) findings", "Complete", "OK", "Information")
        $tabControl.SelectedIndex = 3
    }
    catch {
        Update-Progress "Error: $($_.Exception.Message)" 0
        [System.Windows.Forms.MessageBox]::Show("Assessment failed: $($_.Exception.Message)", "Error", "OK", "Error")
    }
    finally {
        $btnRunAssessment.Enabled = $true
    }
})

$btnExportCSV.Add_Click({
    if ($script:assessmentResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No results to export", "No Data", "OK", "Warning")
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv"
    $saveDialog.FileName = "M365_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        $script:assessmentResults | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        [System.Windows.Forms.MessageBox]::Show("Exported successfully", "Export Complete", "OK", "Information")
    }
})

$btnExportHTML.Add_Click({
    if ($script:assessmentResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No results to export", "No Data", "OK", "Warning")
        return
    }
    
    # FIXED: Calculate counts from actual results
    $criticalCount = @($script:assessmentResults | Where-Object {$_.Severity -eq 'Critical'}).Count
    $highCount = @($script:assessmentResults | Where-Object {$_.Severity -eq 'High'}).Count
    $mediumCount = @($script:assessmentResults | Where-Object {$_.Severity -eq 'Medium'}).Count
    $lowCount = @($script:assessmentResults | Where-Object {$_.Severity -eq 'Low'}).Count
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "HTML files (*.html)|*.html"
    $saveDialog.FileName = "M365_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Copilot Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0; font-size: 36px; }
        .critical-card { background: #ffe6e6; border: 2px solid #ff9999; }
        .high-card { background: #fff5e6; border: 2px solid #ffcc99; }
        .medium-card { background: #ffffe6; border: 2px solid #ffff99; }
        .low-card { background: #e6ffe6; border: 2px solid #99ff99; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        .critical { background: #ffe6e6; }
        .high { background: #fff5e6; }
        .medium { background: #ffffe6; }
        .low { background: #e6ffe6; }
        .details { font-family: 'Consolas', monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>M365 Copilot Security Assessment Report</h1>
        <div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p><strong>Assessment Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Tenant ID:</strong> $($script:tenantId)</p>
            <p><strong>Total Findings:</strong> $($script:assessmentResults.Count)</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical-card">
                <h3>$criticalCount</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high-card">
                <h3>$highCount</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium-card">
                <h3>$mediumCount</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low-card">
                <h3>$lowCount</h3>
                <p>Low</p>
            </div>
        </div>
        
        <h2>Detailed Findings with Data</h2>
        <table>
            <tr>
                <th width="5%">ID</th>
                <th width="20%">Finding</th>
                <th width="35%">Issue & Impact</th>
                <th width="10%">Severity</th>
                <th width="10%">Probability</th>
                <th width="20%">Actual Data</th>
            </tr>
"@
        foreach ($r in $script:assessmentResults) {
            $html += "<tr class='$($r.Severity.ToLower())'>"
            $html += "<td>$($r.ID)</td>"
            $html += "<td><strong>$($r.Finding)</strong></td>"
            $html += "<td>$($r.Issue)</td>"
            $html += "<td><strong>$($r.Severity)</strong></td>"
            $html += "<td>$($r.Probability)</td>"
            $html += "<td class='details'>$($r.Details)</td>"
            $html += "</tr>"
        }
        $html += @"
        </table>
        
        <h2>Priority Actions</h2>
        <ol>
            <li><strong>Critical (Immediate):</strong> Address all Critical findings within 1 week</li>
            <li><strong>High (Short-term):</strong> Resolve High priority items within 1 month</li>
            <li><strong>Medium (Mid-term):</strong> Plan remediation within 3 months</li>
            <li><strong>Low (Long-term):</strong> Include in quarterly reviews</li>
        </ol>
    </div>
</body>
</html>
"@
        $html | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        Start-Process $saveDialog.FileName
    }
})

$form.ShowDialog()