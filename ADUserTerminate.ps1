# Authors: Jascha Mager, Branden Walter
# Last Modified: September 22nd 2024
# ========================
# Description: User Termination Script
# =========================

function SanitizeUser {
    # This function sanitizes a given username. 
    # It extracts the SamAccountName from a UPN if needed and checks for a valid format.
    
    param(
        [String]$User
    )
    
    if ($User -match "^(.+?)@.+$") {
        $User = $matches[1]
        Write-Output "Detected UPN format. Using SamAccountName: $User"
    }

    if ($User -match "^[a-zA-Z0-9\-_]+$") {
        return $User
    } else {
        Write-Output "Invalid username format. Please provide a valid SamAccountName."
        return $null
    }
}

function GetAndValidateUser {
    # This function prompts the user for a valid SamAccountName.
    # It checks if the user exists in Active Directory before returning the user object.

    param(
        [String]$UserId
    )

    while (-not $UserFound) {
        #$UserId = Read-Host -Prompt 'Input the username of the user to be terminated'
        $ADUser = Get-ADUser -Filter {SamAccountName -eq $UserId} -ErrorAction SilentlyContinue

        if ($ADUser) {
            $UserFound = $true
            Write-Host "User found: $($ADUser.Name)"
            return $ADUser
        } else {
            Write-Warning "User not found. Please input a valid username."
        }
    }
}

function ConfirmTermination {
    # This function confirms the termination process with the user.
    # It prompts the admin for confirmation and returns true or false based on input.

    param(
        [String]$UserName
    )

    $confirm = Read-Host "Are you sure you want to terminate user $UserName? (y/n)"
    $confirm = $confirm.Substring(0,1).ToUpper()

    if ($confirm -eq 'Y') {
        return $true
    } else {
        Write-Warning "Termination canceled."
        return $false
    }
}

function ExportGroupMemberships {
    # This function exports the group memberships of the specified user.
    # It saves the group membership information to a CSV file for record-keeping.

    param(
    [String]$UserId, 
    [String]$UserName, 
    [String]$ADGroupReportPath
    )

    $ADGroups = Get-ADPrincipalGroupMembership -Identity $UserId | Where-Object Name -NotLike "Domain Users" | Sort-Object Name
    $GroupMembershipCsv = Join-Path -Path $ADGroupReportPath -ChildPath ("{0}-Groups.csv" -f $UserName)
    
    if (($ADGroups | Measure-Object).Count -GT 0) {
        $ADGroups | Select-Object @{Name="GroupName";Expression={$_.Name}} |
            Export-Csv -Path $GroupMembershipCsv -NoTypeInformation
    } else {
        $NoGroups = [PSCustomObject]@{GroupName = "No Group Memberships"}
        $NoGroups | Export-Csv -Path $GroupMembershipCsv -NoTypeInformation
        Write-Warning "User had no group memberships."
    }

    return $ADGroups
}

function ExportClearedAttributes {
    # This function exports cleared user attributes for documentation purposes.
    # It retrieves attributes like manager, office location, and title, and saves them to a CSV.

    param(
        [Object]$User,
        [String]$UserName,
        [String]$ADGroupReportPath
    )

    $ManagerUPN = "N/A"

    if ($User) {
        try {

            $ADUser = Get-ADUser -Identity $User.SamAccountName -Properties Manager, PhysicalDeliveryOfficeName, FacsimileTelephoneNumber, TelephoneNumber, Title, Department, Company
            $ManagerDN = $ADUser.Manager
            Write-Verbose "User: $($ADUser.Name), Manager DN: $ManagerDN"

            if ($ManagerDN) {
                $Manager = Get-ADUser -Filter "DistinguishedName -eq '$ManagerDN'" -Properties UserPrincipalName

                if ($Manager) {
                    Write-Verbose "Manager found: $($Manager.Name) ($($Manager.UserPrincipalName))"
                    $ManagerUPN = $Manager.UserPrincipalName
                } else {
                    Write-Warning "Manager not found using DistinguishedName: $ManagerDN"
                }
            }

        } catch {
            Write-Warning "Error while retrieving user details: $_"
        }
    }

    $ClearedAttributesList = @(
        [PSCustomObject]@{Attribute="UserName"; Value=$ADUser.Name},
        [PSCustomObject]@{Attribute="ManagerUPN"; Value=$ManagerUPN},
        [PSCustomObject]@{Attribute="PhysicalDeliveryOfficeName"; Value=$ADUser.PhysicalDeliveryOfficeName},
        [PSCustomObject]@{Attribute="FacsimileTelephoneNumber"; Value=$ADUser.FacsimileTelephoneNumber},
        [PSCustomObject]@{Attribute="TelephoneNumber"; Value=$ADUser.TelephoneNumber},
        [PSCustomObject]@{Attribute="Title"; Value=$ADUser.Title},
        [PSCustomObject]@{Attribute="Department"; Value=$ADUser.Department},
        [PSCustomObject]@{Attribute="Company"; Value=$ADUser.Company}
    )

    Write-Output "Exporting The Following User Attributes..."
    Write-Output "#################"

    foreach ($attribute in $ClearedAttributesList) {
        Write-Output "$($attribute.Attribute): $($attribute.Value)"
    }
    Write-Output "#################"
    $ClearedAttributesCsv = Join-Path -Path $ADGroupReportPath -ChildPath ("{0}-ClearedAttributes.csv" -f $UserName)
    $ClearedAttributesList | Export-Csv -Path $ClearedAttributesCsv -NoTypeInformation
}

function TerminateUser {
    # This function handles the termination process for a user.
    # It removes the user from groups, disables their account, and clears sensitive attributes.

    param(
        [String]$UserId, 
        [Object]$ADGroups, 
        [String]$TerminatedOU
    )

    if ($ADGroups.Count -gt 0) {
        Remove-ADPrincipalGroupMembership -Identity $UserId -MemberOf $ADGroups -Confirm:$False
    }

    Disable-ADAccount -Identity $UserId
    Set-ADUser -Identity $UserId -Replace @{msExchHideFromAddressLists = $True}
    Set-ADUser -Identity $UserId -Clear @('manager', 'physicalDeliveryOfficeName','facsimileTelephoneNumber','telephoneNumber','title','department','company')
    Get-ADUser -Identity $UserId | Move-ADObject -TargetPath $TerminatedOU
}

function DisplayScriptInfo {
    # This function displays an aesthetically pleasing message to the user.

    $Header = "#############################"
    $Title = "User Termination Script"
    $Description = "This script will safely terminate a user by removing group memberships, clearing attributes, and disabling the account in Active Directory. Additionally, it will export group memberships and cleared attributes for documentation purposes."
    
    $HeaderColor = "Yellow"
    $TitleColor = "Cyan"
    $DescriptionColor = "Green"
    
    Write-Host $Header -ForegroundColor $HeaderColor
    Write-Host $Title -ForegroundColor $TitleColor
    Write-Host $Header -ForegroundColor $HeaderColor
    Write-Host ""
    Write-Host $Description -ForegroundColor $DescriptionColor
    Write-Host ""
    Write-Host "Please ensure you have the correct user information before proceeding." -ForegroundColor "Red"
    Write-Host ""
    Write-Host $Header -ForegroundColor $HeaderColor
}

function Main{
    # This is the main function orchestrating the termination process.
    # It validates the user, exports group memberships and cleared attributes, and handles termination.

    DisplayScriptInfo
    $TerminatedOU = "OU=Terminated Users,OU=VII Locations,DC=vii,DC=local"
    $ADGroupReportPath = "C:\Windows\SYSVOL\sysvol\vii.local\Scripts\UserTerminations\Allwest"

    $UserId = Read-Host -Prompt 'Input the username of the user to be terminated'
    $ADUser = GetAndValidateUser -UserId $UserId

    if (ConfirmTermination -UserName $ADUser.Name) {
        if (-Not (Test-Path $ADGroupReportPath -PathType Container)) {
            New-Item -Path $ADGroupReportPath -ItemType Directory -Verbose
        }

        $ADGroups = ExportGroupMemberships -UserId $UserId -UserName $ADUser.Name -ADGroupReportPath $ADGroupReportPath
        ExportClearedAttributes -User $ADUser -UserName $ADUser.Name -ADGroupReportPath $ADGroupReportPath
        TerminateUser -UserId $UserId -ADGroups $ADGroups -TerminatedOU $TerminatedOU

        Read-Host -Prompt "Press Enter to exit"
    } else {
        Write-Output "Termination process aborted."
    }
}

Main