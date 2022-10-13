# This script is used to remove phishing mails from everyone's mailbox. WARNING: Although, it
# should only be used to delete phishing mails, it can be used for all kind of mails. Therefore
# be careful when using it!
#
# Helpful information can be found here:
# https://scriptingchris.tech/2021/05/25/how-to-remove-email-from-all-mailboxes-with-powershell/
#
# HINT: If this Cmdlet doesn't work or you get errors like "A parameter cannot be found that matches
# parameter name 'Preview'", you most propably don't have the permission to execute them. Go to
# https://protection.office.com/permissions, select "eDiscovery Manager", "Edit" beside "eDiscovery
# Manager". "Choose eDiscovery Manager" and add yourself as user if you have the permission to do so.

param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Mail Sender"
    )][string]$Sender,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Mail Subject"
    )][string]$Subject,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Mail Content"
    )][string]$Content,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "If the parameter 'Sender' contains a valid mail address he is automatically added to the Phishing mail flow list to avoid future mails"
    )][bool]$BlockSender,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Credential to login without user interaction (does not work, if MFA is active)"
    )][PSCredential]$Credential,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Delete mails without asking (USE ONLY, IF YOU KNOW EXACTLY WHAT YOU ARE DOING!)"
    )][bool]$AutoDelete
);

# Check if Exchange module is installed.
if (!(Get-InstalledModule | Where-Object { $_.Name -eq "ExchangeOnlineManagement" })) {
    Write-Host "Exchange module is not installed. To install it run: Install-Module -Name ExchangeOnlineManagement";
    exit -1;
}

# Function to wait until the specified action completed.
function Wait-ForActionCompletion {
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Action identity"
        )][string]$Identity
    );

    while (($status = (Get-ComplianceSearchAction -Identity $Identity).Status) -and $status -ne "Error" -and $status -ne "Completed") {
        # Wait until the deletion completed.
        Start-Sleep -Seconds 1
    }
}

if (!$Sender -and !$Subject -and !$Content) {
    Write-Warning "No Filter has been provided. Process has been aborted."
} else {
    # Create search name.
    $COMPLIANCE_SEARCH_NAME = "delete-phishing-mail";

    # Try to get a search with the search name.
    $complianceSearch = $null;

    try {
        # Check if sender is a valid mail address (regex from https://www.undocumented-features.com/2021/04/23/easy-powershell-email-address-validation-function/#Solution).
        if ($Sender -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$") {
            if (!$BlockSender) {
                Write-Warning "The sender seems to be a valid mail address. Do you want to add it to the block list?"
                $choicesAdd = [System.Management.Automation.Host.ChoiceDescription[]]("&no", "&yes");
                $BlockSender = $host.UI.PromptForChoice("Add?", "${Sender} seems to be a valid mail address. Do you want to add it to the block list?", $choicesAdd, 0);
            }
        }

        # Connect to Exchange Online.
        if ($Credential) {
            Connect-ExchangeOnline -Credential $Credential | Out-Null;
        } else {
            Connect-ExchangeOnline | Out-Null;
        }

        # Add sender to block list if desired.
        if ($BlockSender) {
            $MAILFLOW_RULE_NAME = "Phishing (Powershell managed)";

            # Try to get the phishing transport rule.
            $rule = Get-TransportRule | Where-Object { $_.Name -eq "${MAILFLOW_RULE_NAME}" };

            $senderAddresses = New-Object System.Collections.ArrayList;
            $senderAddresses.Add($Sender) | Out-Null;

            # If not existent yet, create the rule.
            if (!$rule) {
                New-TransportRule -Name "${MAILFLOW_RULE_NAME}" -Quarantine $true -SetAuditSeverity "High" -FromAddressContainsWords $senderAddresses.ToArray() | Out-Null;
            } else {
                $senderAddresses.AddRange($rule.FromAddressContainsWords);
                Set-TransportRule -Identity $rule.Identity -FromAddressContainsWords ($senderAddresses.ToArray() | Select-Object -Unique) | Out-Null;
            }
        }

        # Connect to Security & Compliance Center.
        if ($Credential) {
            Connect-IPPSSession -Credential $Credential | Out-Null;
        } else {
            Connect-IPPSSession | Out-Null;
        }

        # Try to get a search with the unique search name
        $complianceSearch = Get-ComplianceSearch | Where-Object { $_.Name -eq "${COMPLIANCE_SEARCH_NAME}" };
        
        # If previous search was found, delete it
        if ($complianceSearch) {
            Remove-ComplianceSearch -Identity "${COMPLIANCE_SEARCH_NAME}" -Confirm:$false;
        }

        $parameters = @{
            'From' = "$Sender";
            'Subject' = "$Subject";
            'Message' = "$Content";
        }
        $query = "";

        Write-Host "Creating new compliance search.";
        ForEach ($key in $parameters.Keys) {
            $value = $parameters[$key];

            if ($value) {
                if ($query) {
                    $query += " AND "; # Concatenating query conditions.
                }
                $query += "(${key}:`"${value}`")";
            }
        }
        $complianceSearch = New-ComplianceSearch -Name "${COMPLIANCE_SEARCH_NAME}" -ExchangeLocation All -ContentMatchQuery "${query}";

        # Start compliance search.
        Start-ComplianceSearch -Identity $complianceSearch.Identity;

        # Wait until the search completed.
        Write-Host "Executing search...";
        while (($searchResult = (Get-ComplianceSearch -Identity "${COMPLIANCE_SEARCH_NAME}")) -and $searchResult.status -ne "Error" -and $searchResult.status -ne "Completed") {
            # Wait until the search completed.
            Start-Sleep -Seconds 1;
        }
        $previewAction = New-ComplianceSearchAction -SearchName "${COMPLIANCE_SEARCH_NAME}" -Preview;

        Write-Host "Waiting for results...";
        Wait-ForActionCompletion -Identity $previewAction.Identity;

        # Get results.
        $actionResults = Get-ComplianceSearchAction -Identity $previewAction.Identity -Details;

        # Clean result string.
        $resultString = ($actionResults.Results.TrimStart('{').TrimEnd('}'));

        if ($resultString) {
            $entries = New-Object System.Collections.ArrayList;

            # Usually, the returned result looks something like this:
            # {Location: max.mustermann@company.com; Sender: max.mustermann@company.com; Subject: Suchtest mit Sonderzeichen ; , :; Type: Email; Size: 47955; Received Time: 31.03.2022 08:01:00; Data Link: PreviewResults/Exchange/item_4TsMpFu3af28FLqPkAAIsVmIYAAA==/item.eml,
            # Location: max.mustermann@company.com; Sender: max.mustermann@company.com; Subject: Suchtest; Type: Email; Size: 53378; Received Time: 31.03.2022 07:57:00; Data Link: PreviewResults/Exchange/item_4TsMpFu3af28FLqPkAAIsVmHsAAA==/item.eml}
            #
            # The first step therefore, is to trim the brackets at the start and the end, split the lines into an array and remove the trailing comma.

            # Separate result lines.
            $results = $resultString -split '\n' | ForEach-Object { $_.TrimStart().TrimEnd().TrimEnd(',') };

            # Map result properties.
            foreach ($result in $results) {
                # Each line is matched by a Regex to get properties and values. In the case of "Location: max.mustermann@company.com; Sender: max.mustermann@company.com; Subject: Suchtest; Type: Email;...
                # this leads to:
                # Location: 
                # ; Sender: 
                # ; Subject:
                # and to on...
                $keysRegex = [regex]"(^|; )(\w+ ?\w+): ";

                # The result is split at the property names, which returns an array from which the property
                # names and the corresponding values can be mapped together. E.g.
                #
                #
                # Location
                # max.mustermann@company.com
                # ;
                # Sender
                # max.mustermann@company.com
                # ;
                # Subject
                # Suchtest
                $values = $keysRegex.Split("$result") | Where-Object { $_.Trim() -ne "" };
                $mapping = @{};
                
                # Map properties to values
                for ($i = 0; $i -lt $values.Length; $i += 3) {
                    $mapping[$values[$i]] = $values[$i + 1];
                }
                $entries.Add($mapping) | Out-Null;
            }
            
            # Check if results were found.
            if ($entries.Count -gt 0) {
                $delete = $AutoDelete; # If AutoDelete is set, no further user input is required.

                Write-Host "---------- E-Mails to delete ---------------------------------------------"
                $entries | ForEach-Object { [PSCustomObject]$_ } | Format-Table -AutoSize; # https://stackoverflow.com/a/20874563

                # If auto-deletion is deactivated, ask for permission.
                if (!$delete) {
                    $choicesDelete = [System.Management.Automation.Host.ChoiceDescription[]]("&no", "&yes");
                    $choice = $host.UI.PromptForChoice("Confirmation", "Are you sure you want to delete $($entries.Count) e-mails?", $choicesDelete, 0);

                    if ($choice -eq 1) {
                        $delete = $true;
                    }
                }

                # Delete or abort.
                if ($delete) {
                    $purgeAction = New-ComplianceSearchAction -SearchName "${COMPLIANCE_SEARCH_NAME}" -Purge -PurgeType HardDelete -Force -Confirm:$false;

                    Write-Host "Deleting mails...";
                    Wait-ForActionCompletion -Identity $purgeAction.Identity;
                } else {
                    Write-Warning "Deletion aborted!";
                }
            } else {
                Write-Warning "No e-mails found. Process has been aborted.";
            }
        } else {
            Write-Warning "No results received.";
        }
    } catch {
        Write-Error $_;
    } finally {
        if ($complianceSearch) {
            Remove-ComplianceSearch -Identity "${COMPLIANCE_SEARCH_NAME}" -Confirm:$false;
        }
        Disconnect-ExchangeOnline -Confirm:$false | Out-Null;
    }
}
