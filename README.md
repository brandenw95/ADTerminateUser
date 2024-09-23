# User Termination Script

## Description

This PowerShell script automates the safe termination of a user account in Active Directory. It performs the following actions:

- Validates and sanitizes the provided username.
- Confirms the termination process with the administrator.
- Exports the user's group memberships to a CSV file for documentation.
- Exports cleared user attributes (e.g., manager, office location, title) to a CSV file.
- Removes the user from all groups except "Domain Users".
- Disables the user account.
- Clears sensitive attributes from the user account.
- Moves the user account to a designated "Terminated Users" Organizational Unit (OU).

## Authors

- Jascha Mager
- Branden Walter
