# Delete-Mails.ps1
This script is used to remove phishing mails from everyone's mailbox in an Exchange Online Instance. *WARNING: Although, it should only be used to delete phishing mails, it can be used for all kind of mails. Therefore, **be careful when using it**!*

## Permissions
If this Cmdlet doesn't work or you get errors like "A parameter cannot be found that matches parameter name 'Preview'", you most propably don't have the permission to execute them. Go to https://protection.office.com/permissions, select "eDiscovery Manager", "Edit" beside "eDiscovery Manager". "Choose eDiscovery Manager" and add yourself as user if you have the permission to do so.

## Parameters
| Parameter    | Description                                                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------|
| -Sender      | Mail Sender                                                                                                                           |
| -Subject     | Mail Subject                                                                                                                          |
| -Content     | Mail Content                                                                                                                          |
| -BlockSender | If the parameter -Sender contains a valid mail address he is automatically added to the Phishing mail flow list to avoid future mails |
| -Credential  | Credential to login without user interaction (does not work, if MFA is active)                                                        |
| -AutoDelete  | Delete mails without asking **(USE ONLY, IF YOU KNOW EXACTLY WHAT YOU ARE DOING!)**                                                   |

## Example
```powershell
.\Delete-Mails.ps1 -Sender "phishermansfriend123@example.com" -Subject "You Won!"
```
