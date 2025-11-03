# Configuration Definition
Configuration Windows11_STIG_V2R4 {
    param (
        [string[]]$NodeName ='localhost'
        )
 
    # Import PSDscResources so resources are packaged for Guest Configuration (avoid PSDesiredStateConfiguration dependency)
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0
    Import-DscResource -ModuleName 'AuditPolicyDsc' -ModuleVersion 1.4.0.0
    Import-DscResource -ModuleName 'SecurityPolicyDsc' -ModuleVersion 2.10.0.0
 
    Node $NodeName {
        AccountPolicy 'V-253300 (MEDIUM) The password history must be configured to 24 passwords remembered.'
        {
            # V-253300 (MEDIUM) The password history must be configured to 24 passwords remembered.
            Name                                        = 'V-253300 (MEDIUM) The password history must be configured to 24 passwords remembered.'
            Enforce_password_history                    = 24
        }
        AccountPolicy 'V-253301 (MEDIUM) The maximum password age must be configured to 60 days or less.'
        {
            #  V-253301 (MEDIUM) The maximum password age must be configured to 60 days or less.
            Name                                        = 'V-253301 (MEDIUM) The maximum password age must be configured to 60 days or less.'
            Maximum_Password_Age                        = 60
        }
        AccountPolicy 'V-253302 (MEDIUM) The minimum password age must be configured to at least 1 day.'
        {
            # V-253302 (MEDIUM) The minimum password age must be configured to at least 1 day.
            Name                                        = 'V-253302 (MEDIUM) The minimum password age must be configured to at least 1 day.'
            Minimum_Password_Age                        = 1
        }
        AccountPolicy 'V-253303 (MEDIUM) Passwords must, at a minimum, be 14 characters.'
        {
            # V-253303 (MEDIUM) Passwords must, at a minimum, be 14 characters.
            Name                                        = 'V-253303 (MEDIUM) Passwords must, at a minimum, be 14 characters.'
            Minimum_Password_Length                     = 14
        }
        AccountPolicy 'V-253304 (MEDIUM) The built-in Microsoft password complexity filter must be enabled.'
        {
            # V-253304 (MEDIUM) The built-in Microsoft password complexity filter must be enabled.
            Name                                        = 'V-253304 (MEDIUM) The built-in Microsoft password complexity filter must be enabled.'
            Password_must_meet_complexity_requirements  = 'Enabled'
        }
        AccountPolicy 'V-253305 (HIGH) Reversible password encryption must be disabled.'
        {
            # V-253305 (HIGH) Reversible password encryption must be disabled.
            Name                                        = 'V-253305 (HIGH) Reversible password encryption must be disabled.'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
        AccountPolicy 'V-253298 (MEDIUM) The number of allowed bad logon attempts must be configured to three or less.'
        {
            # V-253298 (MEDIUM) The number of allowed bad logon attempts must be configured to three or less.
            Name                                        = 'V-253298 (MEDIUM) The number of allowed bad logon attempts must be configured to three or less.'
            Account_lockout_threshold                   = 3
        }
        AccountPolicy 'V-253297 (MEDIUM) Windows 11 account lockout duration must be configured to 15 minutes or greater.'
        {
            # V-253297 (MEDIUM) Windows 11 account lockout duration must be configured to 15 minutes or greater.
            Name                                        = 'V-253297 (MEDIUM) Windows 11 account lockout duration must be configured to 15 minutes or greater.'
            Account_lockout_duration                    = 15
        }
        AccountPolicy 'V-253299 (MEDIUM) The period of time before the bad logon counter is reset must be configured to 15 minutes.'
        {
            # V-253299 (MEDIUM) The period of time before the bad logon counter is reset must be configured to 15 minutes.
            Name                                        = 'V-253299 (MEDIUM) The period of time before the bad logon counter is reset must be configured to 15 minutes.'
            Reset_account_lockout_counter_after         = 15
        }

        # V-253418 (HIGH) The Windows Remote Management (WinRM) service must not use Basic authentication.
        Registry 'V-253418 (HIGH) The Windows Remote Management (WinRM) service must not use Basic authentication.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueName   = 'AllowBasic'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253416 (HIGH) The Windows Remote Management (WinRM) client must not use Basic authentication.
        Registry 'V-253416 (HIGH) The Windows Remote Management (WinRM) client must not use Basic authentication.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName   = 'AllowBasic'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253411 (HIGH) The Windows Installer feature "Always install with elevated privileges" must be disabled.
        Registry 'V-253411 (HIGH) The Windows Installer feature "Always install with elevated privileges" must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName   = 'AlwaysInstallElevated'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253462 (HIGH) The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
        Registry 'V-253462 (HIGH) The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Control\Lsa'
            ValueName   = 'LmCompatibilityLevel'
            ValueType   = 'DWord'
            ValueData   = '5'
            Force       = $true
        }
        # V-253284 (HIGH) Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.
        Registry 'V-253284 (HIGH) Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Control\Session Manager\kernel'
            ValueName   = 'DisableExceptionChainValidation'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253461 (HIGH) The system must be configured to prevent the storage of the LAN Manager hash of passwords.
        Registry 'V-253461 (HIGH) The system must be configured to prevent the storage of the LAN Manager hash of passwords.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Control\Lsa'
            ValueName   = 'NoLMHash'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253458 (MEDIUM) NTLM must be prevented from falling back to a Null session.
        Registry 'V-253458 (MEDIUM) NTLM must be prevented from falling back to a Null session.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'
            ValueName   = 'allownullsessionfallback'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253456 (HIGH) Anonymous access to Named Pipes and Shares must be restricted.
        Registry 'V-253456 (HIGH) Anonymous access to Named Pipes and Shares must be restricted.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName   = 'RestrictNullSessAccess'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253455 (MEDIUM) The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
        Registry 'V-253455 (MEDIUM) The system must be configured to prevent anonymous users from having the same rights as the Everyone group.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName   = 'EveryoneIncludesAnonymous'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253454 (HIGH) Anonymous enumeration of shares must be restricted.
        Registry 'V-253454 (HIGH) Anonymous enumeration of shares must be restricted.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Control\Lsa'
            ValueName   = 'RestrictAnonymous'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253453 (HIGH) Anonymous enumeration of SAM accounts must not be allowed.
        Registry 'V-253453 (HIGH) Anonymous enumeration of SAM accounts must not be allowed.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Control\Lsa'
            ValueName   = 'RestrictAnonymousSAM'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253451 (MEDIUM) The Windows SMB server must be configured to always perform SMB packet signing.
        Registry 'V-253451 (MEDIUM) The Windows SMB server must be configured to always perform SMB packet signing.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName   = 'RequireSecuritySignature'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253450 (MEDIUM) Unencrypted passwords must not be sent to third-party SMB Servers.
        Registry 'V-253450 (MEDIUM) Unencrypted passwords must not be sent to third-party SMB Servers.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            ValueName   = 'EnablePlainTextPassword'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253449 (MEDIUM) The Windows SMB client must be configured to always perform SMB packet signing.
        Registry 'V-253449 (MEDIUM) The Windows SMB client must be configured to always perform SMB packet signing.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            ValueName   = 'RequireSecuritySignature'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253448 (MEDIUM) The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
        Registry 'V-253448 (MEDIUM) The Smart Card removal option must be configured to Force Logoff or Lock Workstation.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName   = 'SCRemoveOption'
            ValueType   = 'String'
            ValueData   = '1'
            Force       = $true
        }
        # V-253445 (MEDIUM) The required legal notice must be configured to display before console logon.
        Registry 'V-253445 (MEDIUM) The required legal notice must be configured to display before console logon.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'LegalNoticeText'
            ValueType   = 'String'
            ValueData   = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
            Force       = $true
        }
        # V-253446 (LOW) The Windows message title for the legal notice must be configured.
        Registry 'V-253446 (LOW) The Windows message title for the legal notice must be configured.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'LegalNoticeCaption'
            ValueType   = 'String'
            ValueData   = 'DoD Notice and Consent Banner'
            Force       = $true
        }
        # V-253477 (LOW) Toast notifications to the lock screen must be turned off.
        Registry 'V-253477 (LOW) Toast notifications to the lock screen must be turned off.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
            ValueName   = 'NoToastApplicationNotificationOnLockScreen'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253475 (MEDIUM) User Account Control must virtualize file and registry write failures to per-user locations.
        Registry 'V-253475 (MEDIUM) User Account Control must virtualize file and registry write failures to per-user locations.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'EnableVirtualization'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253474 (MEDIUM) User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
        Registry 'V-253474 (MEDIUM) User Account Control must run all administrators in Admin Approval Mode, enabling UAC.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'EnableLUA'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253473 (MEDIUM) User Account Control must only elevate UIAccess applications that are installed in secure locations.
        Registry 'V-253473 (MEDIUM) User Account Control must only elevate UIAccess applications that are installed in secure locations.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'EnableSecureUIAPaths'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253472 (MEDIUM) User Account Control must be configured to detect application installations and prompt for elevation.
        Registry 'V-253472 (MEDIUM) User Account Control must be configured to detect application installations and prompt for elevation.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'EnableInstallerDetection'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253466 (MEDIUM) The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
        Registry 'V-253466 (MEDIUM) The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
            ValueName   = 'Enabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253465 (MEDIUM) The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.
        Registry 'V-253465 (MEDIUM) The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName   = 'NTLMMinServerSec'
            ValueType   = 'DWord'
            ValueData   = '537395200'
            Force       = $true
        }
        # V-253464 (MEDIUM) The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.
        Registry 'V-253464 (MEDIUM) The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName   = 'NTLMMinClientSec'
            ValueType   = 'DWord'
            ValueData   = '537395200'
            Force       = $true
        }
        # V-253463 (MEDIUM) The system must be configured to the required LDAP client signing level.
        Registry 'V-253463 (MEDIUM) The system must be configured to the required LDAP client signing level.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
            ValueName   = 'LDAPClientIntegrity'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253460 (MEDIUM) Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
        Registry 'V-253460 (MEDIUM) Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueName   = 'SupportedEncryptionTypes'
            ValueType   = 'DWord'
            ValueData   = '2147483640'
            Force       = $true
        }
        # V-253382 (HIGH) Solicited Remote Assistance must not be allowed.
        Registry 'V-253382 (HIGH) Solicited Remote Assistance must not be allowed.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fAllowToGetHelp'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253386 (HIGH) Autoplay must be turned off for non-volume devices.
        Registry 'V-253386 (HIGH) Autoplay must be turned off for non-volume devices.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName   = 'NoAutoplayfornonVolume'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253388 (HIGH) Autoplay must be disabled for all drives.
        Registry 'V-253388 (HIGH) Autoplay must be disabled for all drives.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoDriveTypeAutoRun'
            ValueType   = 'DWord'
            ValueData   = '255'
            Force       = $true
        }
        # V-253387 (HIGH) The default autorun behavior must be configured to prevent autorun commands.
        Registry 'V-253387 (HIGH) The default autorun behavior must be configured to prevent autorun commands.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoAutorun'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253370 (HIGH) Credential Guard must be running on Windows 11 domain-joined systems.
        Registry 'V-253370 (HIGH) Credential Guard must be running on Windows 11 domain-joined systems.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueName   = 'LsaCfgFlags'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253355 (LOW) The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.
        Registry 'V-253355 (LOW) The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'EnableICMPRedirect'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-257592 (MEDIUM) Windows 11 must not have portproxy enabled or in use.
        Registry 'V-257592 (MEDIUM) Windows 11 must not have portproxy enabled or in use.' {
            Ensure      = 'Absent'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy'
            ValueName   = 'v4tov4\tcp'
        }
        ### To find the audit policy subcategory names, run the following command in PowerShell: auditpol /get /category:*
        # V-253307 (MEDIUM) The system must be configured to audit Account Logon - Credential Validation successes.
        AuditPolicySubcategory "V-253307 (MEDIUM) The system must be configured to audit Account Logon - Credential Validation successes."
        {
            Name      = 'Credential Validation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253306 (MEDIUM) The system must be configured to audit Account Logon - Credential Validation failures.
        AuditPolicySubcategory "V-253306 (MEDIUM) The system must be configured to audit Account Logon - Credential Validation failures."
        {
            Name      = 'Credential Validation'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253308 (MEDIUM) The system must be configured to audit Account Management - Security Group Management successes.
        AuditPolicySubcategory "V-253308 (MEDIUM) The system must be configured to audit Account Management - Security Group Management successes."
        {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253310 (MEDIUM) The system must be configured to audit Account Management - User Account Management successes.
        AuditPolicySubcategory "V-253310 (MEDIUM) The system must be configured to audit Account Management - User Account Management successes."
        {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253309 (MEDIUM) The system must be configured to audit Account Management - User Account Management failures.
        AuditPolicySubcategory "V-253309 (MEDIUM) The system must be configured to audit Account Management - User Account Management failures."
        {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253311 (MEDIUM) The system must be configured to audit Detailed Tracking - PNP Activity successes.
        AuditPolicySubcategory "V-253311 (MEDIUM) The system must be configured to audit Detailed Tracking - PNP Activity successes."
        {
            Name      = 'Plug and Play Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253312 (MEDIUM) The system must be configured to audit Detailed Tracking - Process Creation successes.
        AuditPolicySubcategory "V-253312 (MEDIUM) The system must be configured to audit Detailed Tracking - Process Creation successes."
        {
            Name      = 'Process Creation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-257770 (MEDIUM) Windows 11 must have command line process auditing events enabled for failures.
        AuditPolicySubcategory "V-257770 (MEDIUM) Windows 11 must have command line process auditing events enabled for failures."
        {
            Name      = 'Process Creation'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253313 (MEDIUM) The system must be configured to audit Logon/Logoff - Account Lockout failures.
        AuditPolicySubcategory "V-253313 (MEDIUM) The system must be configured to audit Logon/Logoff - Account Lockout failures."
        {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253314 (MEDIUM) The system must be configured to audit Logon/Logoff - Group Membership successes.
        AuditPolicySubcategory "V-253314 (MEDIUM) The system must be configured to audit Logon/Logoff - Group Membership successes."
        {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253315 (MEDIUM) The system must be configured to audit Logon/Logoff - Logoff successes.
        AuditPolicySubcategory "V-253315 (MEDIUM) The system must be configured to audit Logon/Logoff - Logoff successes."
        {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253316 (MEDIUM) The system must be configured to audit Logon/Logoff - Logon failures.
        AuditPolicySubcategory "V-253316 (MEDIUM) The system must be configured to audit Logon/Logoff - Logon failures."
        {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253317 (MEDIUM) The system must be configured to audit Logon/Logoff - Logon successes.
        AuditPolicySubcategory "V-253317 (MEDIUM) The system must be configured to audit Logon/Logoff - Logon successes."
        {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253318 (MEDIUM) The system must be configured to audit Logon/Logoff - Special Logon successes.
        AuditPolicySubcategory "V-253318 (MEDIUM) The system must be configured to audit Logon/Logoff - Special Logon successes."
        {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253319 (MEDIUM) Windows 11 must be configured to audit Object Access - File Share failures.
        AuditPolicySubcategory "V-253319 (MEDIUM) Windows 11 must be configured to audit Object Access - File Share failures."
        {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253320 (MEDIUM) The system must be configured to audit Object Access - File Share successes.
        AuditPolicySubcategory "V-253320 (MEDIUM) The system must be configured to audit Object Access - File Share successes."
        {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253321 (MEDIUM) Windows 11 must be configured to audit Object Access - Other Object Access Events successes.
        AuditPolicySubcategory "V-253321 (MEDIUM) Windows 11 must be configured to audit Object Access - Other Object Access Events successes."
        {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253322 (MEDIUM) Windows 11 must be configured to audit Object Access - Other Object Access Events failures.
        AuditPolicySubcategory "V-253322 (MEDIUM) Windows 11 must be configured to audit Object Access - Other Object Access Events failures."
        {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253323 (MEDIUM) The system must be configured to audit Object Access - Removable Storage failures.
        AuditPolicySubcategory "V-253323 (MEDIUM) The system must be configured to audit Object Access - Removable Storage failures."
        {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253324 (MEDIUM) The system must be configured to audit Object Access - Removable Storage successes.
        AuditPolicySubcategory "V-253324 (MEDIUM) The system must be configured to audit Object Access - Removable Storage successes."
        {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253325 (MEDIUM) The system must be configured to audit Policy Change - Audit Policy Change successes.
        AuditPolicySubcategory "V-253325 (MEDIUM) The system must be configured to audit Policy Change - Audit Policy Change successes."
        {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253326 (MEDIUM) The system must be configured to audit Policy Change - Authentication Policy Change successes.
        AuditPolicySubcategory "V-253326 (MEDIUM) The system must be configured to audit Policy Change - Authentication Policy Change successes."
        {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253327 (MEDIUM) The system must be configured to audit Policy Change - Authorization Policy Change successes.
        AuditPolicySubcategory "V-253327 (MEDIUM) The system must be configured to audit Policy Change - Authorization Policy Change successes."
        {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253328 (MEDIUM) The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.
        AuditPolicySubcategory "V-253328 (MEDIUM) The system must be configured to audit Privilege Use - Sensitive Privilege Use failures."
        {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253329 (MEDIUM) The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.
        AuditPolicySubcategory "V-253329 (MEDIUM) The system must be configured to audit Privilege Use - Sensitive Privilege Use successes."
        {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253330 (MEDIUM) The system must be configured to audit System - IPsec Driver failures.
        AuditPolicySubcategory "V-253330 (MEDIUM) The system must be configured to audit System - IPsec Driver failures."
        {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253331 (MEDIUM) The system must be configured to audit System - Other System Events successes.
        AuditPolicySubcategory "V-253331 (MEDIUM) The system must be configured to audit System - Other System Events successes."
        {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253332 (MEDIUM) The system must be configured to audit System - Other System Events failure.
        AuditPolicySubcategory "V-253332 (MEDIUM) The system must be configured to audit System - Other System Events failure."
        {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253333 (MEDIUM) The system must be configured to audit System - Security State Change successes.
        AuditPolicySubcategory "V-253333 (MEDIUM) The system must be configured to audit System - Security State Change successes."
        {
            Name      = 'Security State Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253334 (MEDIUM) The system must be configured to audit System - Security System Extension successes.
        AuditPolicySubcategory "V-253334 (MEDIUM) The system must be configured to audit System - Security System Extension successes."
        {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253335 (MEDIUM) The system must be configured to audit System - System Integrity failures.
        AuditPolicySubcategory "V-253335 (MEDIUM) The system must be configured to audit System - System Integrity failures."
        {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253336 (MEDIUM) The system must be configured to audit System - System Integrity successes.
        AuditPolicySubcategory "V-253336 (MEDIUM) The system must be configured to audit System - System Integrity successes."
        {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253490 (HIGH) The "Debug programs" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253490 (HIGH) The "Debug programs" user right must only be assigned to the Administrators group.' {
            Policy       = 'Debug_programs'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253349 (MEDIUM) Windows 11 must be configured to audit MPSSVC Rule-Level Policy Change Failures.
        AuditPolicySubcategory "V-253349 (MEDIUM) Windows 11 must be configured to audit MPSSVC Rule-Level Policy Change Failures."
        {
            Name      = 'MPSSVC Rule-Level Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253348 (MEDIUM) Windows 11 must be configured to audit MPSSVC Rule-Level Policy Change Successes.
        AuditPolicySubcategory "V-253348 (MEDIUM) Windows 11 must be configured to audit MPSSVC Rule-Level Policy Change Successes."
        {
            Name      = 'MPSSVC Rule-Level Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253347 (MEDIUM) Windows 11 must be configured to audit Detailed File Share Failures.
        AuditPolicySubcategory "V-253347 (MEDIUM) Windows 11 must be configured to audit Detailed File Share Failures."
        {
            Name      = 'Detailed File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253346 (MEDIUM) Windows 11 must be configured to audit other Logon/Logoff Events Failures.
        AuditPolicySubcategory "V-253346 (MEDIUM) Windows 11 must be configured to audit other Logon/Logoff Events Failures."
        {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253345 (MEDIUM) Windows 11 must be configured to audit other Logon/Logoff Events Successes.
        AuditPolicySubcategory "V-253345 (MEDIUM) Windows 11 must be configured to audit other Logon/Logoff Events Successes."
        {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253344 (MEDIUM) Windows 11 must be configured to audit Other Policy Change Events Failures.
        AuditPolicySubcategory "V-253344 (MEDIUM) Windows 11 must be configured to audit Other Policy Change Events Failures."
        {
            Name      = 'Other Policy Change Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        # V-253343 (MEDIUM) Windows 11 must be configured to audit Other Policy Change Events Successes.
        AuditPolicySubcategory "V-253343 (MEDIUM) Windows 11 must be configured to audit Other Policy Change Events Successes."
        {
            Name      = 'Other Policy Change Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # V-253486 (HIGH) The "Create a token object" user right must not be assigned to any groups or accounts.
        UserRightsAssignment 'V-253486 (HIGH) The "Create a token object" user right must not be assigned to any groups or accounts.' {
            Policy       = 'Create_a_token_object'
            Identity     = ''
            Force        = $true
        }
        # V-253481 (HIGH) The "Act as part of the operating system" user right must not be assigned to any groups or accounts.
        UserRightsAssignment 'V-253481 (HIGH) The "Act as part of the operating system" user right must not be assigned to any groups or accounts.' {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
            Force        = $true
        }
        # V-253506 (MEDIUM) The "Take ownership of files or other objects" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253506 (MEDIUM) The "Take ownership of files or other objects" user right must only be assigned to the Administrators group.' {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253505 (MEDIUM) The "Restore files and directories" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253505 (MEDIUM) The "Restore files and directories" user right must only be assigned to the Administrators group.' {
            Policy       = 'Restore_files_and_directories'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253504 (MEDIUM) The "Profile single process" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253504 (MEDIUM) The "Profile single process" user right must only be assigned to the Administrators group.' {
            Policy       = 'Profile_single_process'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253503 (MEDIUM) The "Perform volume maintenance tasks" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253503 (MEDIUM) The "Perform volume maintenance tasks" user right must only be assigned to the Administrators group.' {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253502 (MEDIUM) The "Modify firmware environment values" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253502 (MEDIUM) The "Modify firmware environment values" user right must only be assigned to the Administrators group.' {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253501 (MEDIUM) The "Manage auditing and security log" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253501 (MEDIUM) The "Manage auditing and security log" user right must only be assigned to the Administrators group.' {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253500 (MEDIUM) The "Lock pages in memory" user right must not be assigned to any groups or accounts.
        UserRightsAssignment 'V-253500 (MEDIUM) The "Lock pages in memory" user right must not be assigned to any groups or accounts.' {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
            Force        = $true
        }
        # V-253499 (MEDIUM) The "Load and unload device drivers" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253499 (MEDIUM) The "Load and unload device drivers" user right must only be assigned to the Administrators group.' {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253498 (MEDIUM) The "Impersonate a client after authentication" user right must only be assigned to Administrators, Service, Local Service, and Network Service.
        UserRightsAssignment 'V-253498 (MEDIUM) The "Impersonate a client after authentication" user right must only be assigned to Administrators, Service, Local Service, and Network Service.' {
            Policy       = 'Impersonate_a_client_after_authentication'
            Identity     = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE')
            Force        = $true
        }
        # V-253497 (MEDIUM) The "Force shutdown from a remote system" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253497 (MEDIUM) The "Force shutdown from a remote system" user right must only be assigned to the Administrators group.' {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253496 (MEDIUM) The "Enable computer and user accounts to be trusted for delegation" user right must not be assigned to any groups or accounts.
        UserRightsAssignment 'V-253496 (MEDIUM) The "Enable computer and user accounts to be trusted for delegation" user right must not be assigned to any groups or accounts.' {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
            Force        = $true
        }
        # V-253495 (MEDIUM) The "Deny log on through Remote Desktop Services" user right on Windows 11 workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.
        UserRightsAssignment 'V-253495 (MEDIUM) The "Deny log on through Remote Desktop Services" user right on Windows 11 workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.' {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
        }
        # V-253494 (MEDIUM) The "Deny log on locally" user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.
        UserRightsAssignment 'V-253494 (MEDIUM) The "Deny log on locally" user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.' {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
        }
        # V-253493 (MEDIUM) The "Deny log on as a service" user right on Windows 11 domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
        UserRightsAssignment 'V-253493 (MEDIUM) The "Deny log on as a service" user right on Windows 11 domain-joined workstations must be configured to prevent access from highly privileged domain accounts.' {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
        }
        # V-253492 (MEDIUM) The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
        UserRightsAssignment 'V-253492 (MEDIUM) The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.' {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
        }
        # V-253491 (MEDIUM) The "Deny access to this computer from the network" user right on workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.
        UserRightsAssignment 'V-253491 (MEDIUM) The "Deny access to this computer from the network" user right on workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.' {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests'
        }
        # V-253489 (MEDIUM) The "Create symbolic links" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253489 (MEDIUM) The "Create symbolic links" user right must only be assigned to the Administrators group.' {
            Policy       = 'Create_symbolic_links'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253487 (MEDIUM) The "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.
        UserRightsAssignment 'V-253487 (MEDIUM) The "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.' {
            Policy       = 'Create_global_objects'
            Identity     = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE')
            Force        = $true
        }
        # V-253485 (MEDIUM) The "Create a pagefile" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253485 (MEDIUM) The "Create a pagefile" user right must only be assigned to the Administrators group.' {
            Policy       = 'Create_a_pagefile'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253484 (MEDIUM) The "Change the system time" user right must only be assigned to Administrators and Local Service.
        UserRightsAssignment 'V-253484 (MEDIUM) The "Change the system time" user right must only be assigned to Administrators and Local Service.' {
            Policy       = 'Change_the_system_time'
            Identity     = @('Administrators','LOCAL SERVICE')
            Force        = $true
        }
        # V-253483 (MEDIUM) The "Back up files and directories" user right must only be assigned to the Administrators group.
        UserRightsAssignment 'V-253483 (MEDIUM) The "Back up files and directories" user right must only be assigned to the Administrators group.' {
            Policy       = 'Back_up_files_and_directories'
            Identity     = @('Administrators')
            Force        = $true
        }
        # V-253482 (MEDIUM) The "Allow log on locally" user right must only be assigned to the Administrators and Users groups.
        UserRightsAssignment 'V-253482 (MEDIUM) The "Allow log on locally" user right must only be assigned to the Administrators and Users groups.' {
            Policy       = 'Allow_log_on_locally'
            Identity     = @('Administrators','Users')
            Force        = $true
        }
        # V-253480 (MEDIUM) The "Access this computer from the network" user right must only be assigned to the Administrators and Remote Desktop Users groups.
        UserRightsAssignment 'V-253480 (MEDIUM) The "Access this computer from the network" user right must only be assigned to the Administrators and Remote Desktop Users groups.' {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = @('Administrators','Remote Desktop Users')
            Force        = $true
        }
        # V-253479 (MEDIUM) The "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts.
        UserRightsAssignment 'V-253479 (MEDIUM) The "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts.' {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
            Force        = $true
        }
        # V-253478 (MEDIUM) Zone information must be preserved when saving attachments.
        Registry 'V-253478 (MEDIUM) Zone information must be preserved when saving attachments.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
            ValueName   = 'SaveZoneInformation'
            ValueType   = 'DWord'
            ValueData   = '2'
            Force       = $true
        }
        # V-253426 (MEDIUM) Windows 11 Kernel (Direct Memory Access) DMA Protection must be enabled.
        Registry 'V-253426 (MEDIUM) Windows 11 Kernel (Direct Memory Access) DMA Protection must be enabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
            ValueName   = 'DeviceEnumerationPolicy'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253424 (MEDIUM) Windows Ink Workspace must be configured to disallow access above the lock.
        Registry 'V-253424 (MEDIUM) Windows Ink Workspace must be configured to disallow access above the lock.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
            ValueName   = 'AllowWindowsInkWorkspace'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253423 (MEDIUM) The convenience PIN for Windows 11 must be disabled.
        Registry 'V-253423 (MEDIUM) The convenience PIN for Windows 11 must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName   = 'AllowDomainPINLogon'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253421 (MEDIUM) The Windows Remote Management (WinRM) client must not use Digest authentication.
        Registry 'V-253421 (MEDIUM) The Windows Remote Management (WinRM) client must not use Digest authentication.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName   = 'AllowDigest'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253420 (MEDIUM) The Windows Remote Management (WinRM) service must not store RunAs credentials.
        Registry 'V-253420 (MEDIUM) The Windows Remote Management (WinRM) service must not store RunAs credentials.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueName   = 'DisableRunAs'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253419 (MEDIUM) The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
        Registry 'V-253419 (MEDIUM) The Windows Remote Management (WinRM) service must not allow unencrypted traffic.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueName   = 'AllowUnencryptedTraffic'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253417 (MEDIUM) The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
        Registry 'V-253417 (MEDIUM) The Windows Remote Management (WinRM) client must not allow unencrypted traffic.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName   = 'AllowUnencryptedTraffic'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253415 (MEDIUM) PowerShell Transcription must be enabled on Windows 11.
        Registry 'V-253415 (MEDIUM) PowerShell Transcription must be enabled on Windows 11.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName   = 'EnableTranscripting'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253414 (MEDIUM) PowerShell script block logging must be enabled on Windows 11.
        Registry 'V-253414 (MEDIUM) PowerShell script block logging must be enabled on Windows 11.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName   = 'EnableScriptBlockLogging'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253413 (MEDIUM) Automatically signing in the last interactive user after a system-initiated restart must be disabled.
        Registry 'V-253413 (MEDIUM) Automatically signing in the last interactive user after a system-initiated restart must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'DisableAutomaticRestartSignOn'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253412 (MEDIUM) Users must be notified if a web-based program attempts to install software.
        Registry 'V-253412 (MEDIUM) Users must be notified if a web-based program attempts to install software.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName   = 'SafeForScripting'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253410 (MEDIUM) Users must be prevented from changing installation options.
        Registry 'V-253410 (MEDIUM) Users must be prevented from changing installation options.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName   = 'EnableUserControl'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253409 (MEDIUM) Indexing of encrypted files must be turned off.
        Registry 'V-253409 (MEDIUM) Indexing of encrypted files must be turned off.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName   = 'AllowIndexingEncryptedStoresOrItems'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253408 (MEDIUM) Basic authentication for RSS feeds over HTTP must not be used.
        Registry 'V-253408 (MEDIUM) Basic authentication for RSS feeds over HTTP must not be used.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName   = 'AllowBasicAuthInClear'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253407 (MEDIUM) Attachments must be prevented from being downloaded from RSS feeds.
        Registry 'V-253407 (MEDIUM) Attachments must be prevented from being downloaded from RSS feeds.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName   = 'DisableEnclosureDownload'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253406 (MEDIUM) Remote Desktop Services must be configured with the client connection encryption set to the required level.
        Registry 'V-253406 (MEDIUM) Remote Desktop Services must be configured with the client connection encryption set to the required level.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'MinEncryptionLevel'
            ValueType   = 'DWord'
            ValueData   = '3'
            Force       = $true
        }
        # V-253405 (MEDIUM) The Remote Desktop Session Host must require secure RPC communications.
        Registry 'V-253405 (MEDIUM) The Remote Desktop Session Host must require secure RPC communications.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fEncryptRPCTraffic'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253404 (MEDIUM) Remote Desktop Services must always prompt a client for passwords upon connection.
        Registry 'V-253404 (MEDIUM) Remote Desktop Services must always prompt a client for passwords upon connection.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fPromptForPassword'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253403 (MEDIUM) Local drives must be prevented from sharing with Remote Desktop Session Hosts.
        Registry 'V-253403 (MEDIUM) Local drives must be prevented from sharing with Remote Desktop Session Hosts.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fDisableCdm'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253402 (MEDIUM) Passwords must not be saved in the Remote Desktop Client.
        Registry 'V-253402 (MEDIUM) Passwords must not be saved in the Remote Desktop Client.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'DisablePasswordSaving'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253401 (MEDIUM) Windows 11 must be configured to require a minimum pin length of six characters or greater.
        Registry 'V-253401 (MEDIUM) Windows 11 must be configured to require a minimum pin length of six characters or greater.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
            ValueName   = 'MinimumPINLength'
            ValueType   = 'DWord'
            ValueData   = '6'
            Force       = $true
        }
        # V-253400 (MEDIUM) The use of a hardware security device with Windows Hello for Business must be enabled.
        Registry 'V-253400 (MEDIUM) The use of a hardware security device with Windows Hello for Business must be enabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
            ValueName   = 'RequireSecurityDevice'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253399 (MEDIUM) Windows 11 must be configured to disable Windows Game Recording and Broadcasting.
        Registry 'V-253399 (MEDIUM) Windows 11 must be configured to disable Windows Game Recording and Broadcasting.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            ValueName   = 'AllowGameDVR'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253398 (MEDIUM) File Explorer shell protocol must run in protected mode.
        Registry 'V-253398 (MEDIUM) File Explorer shell protocol must run in protected mode.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'PreXPSP2ShellProtocolBehavior'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253396 (MEDIUM) Explorer Data Execution Prevention must be enabled.
        Registry 'V-253396 (MEDIUM) Explorer Data Execution Prevention must be enabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName   = 'NoDataExecutionPrevention'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253395 (MEDIUM) The Microsoft Defender SmartScreen for Explorer must be enabled.
        Registry 'V-253395 (MEDIUM) The Microsoft Defender SmartScreen for Explorer must be enabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'ShellSmartScreenLevel'
            ValueType   = 'String'
            ValueData   = 'Block'
            Force       = $true
        }
        # V-253393 (MEDIUM) Windows Telemetry must not be configured to Full.
        Registry 'V-253393 (MEDIUM) Windows Telemetry must not be configured to Full.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253392 (MEDIUM) Enhanced diagnostic data must be limited to the minimum required to support Windows Analytics.
        Registry 'V-253392 (MEDIUM) Enhanced diagnostic data must be limited to the minimum required to support Windows Analytics.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253391 (MEDIUM) Administrator accounts must not be enumerated during elevation.
        Registry 'V-253391 (MEDIUM) Administrator accounts must not be enumerated during elevation.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName   = 'EnumerateAdministrators'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253389 (MEDIUM) Enhanced anti-spoofing for facial recognition must be enabled on Windows 11.
        Registry 'V-253389 (MEDIUM) Enhanced anti-spoofing for facial recognition must be enabled on Windows 11.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
            ValueName   = 'EnhancedAntiSpoofing'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253383 (MEDIUM) Unauthenticated RPC clients must be restricted from connecting to the RPC server.
        Registry 'V-253383 (MEDIUM) Unauthenticated RPC clients must be restricted from connecting to the RPC server.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName   = 'RestrictRemoteClients'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253381 (MEDIUM) The user must be prompted for a password on resume from sleep (plugged in).
        Registry 'V-253381 (MEDIUM) The user must be prompted for a password on resume from sleep (plugged in).' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName   = 'ACSettingIndex'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253380 (MEDIUM) Users must be prompted for a password on resume from sleep (on battery).
        Registry 'V-253380 (MEDIUM) Users must be prompted for a password on resume from sleep (on battery).' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName   = 'DCSettingIndex'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253379 (MEDIUM) Local users on domain-joined computers must not be enumerated.
        Registry 'V-253379 (MEDIUM) Local users on domain-joined computers must not be enumerated.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'EnumerateLocalUsers'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253378 (MEDIUM) The network selection user interface (UI) must not be displayed on the logon screen.
        Registry 'V-253378 (MEDIUM) The network selection user interface (UI) must not be displayed on the logon screen.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'DontDisplayNetworkSelectionUI'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253377 (MEDIUM) Systems must at least attempt device authentication using certificates.
        Registry 'V-253377 (MEDIUM) Systems must at least attempt device authentication using certificates.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueName   = 'DevicePKInitEnabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253376 (MEDIUM) Printing over HTTP must be prevented.
        Registry 'V-253376 (MEDIUM) Printing over HTTP must be prevented.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName   = 'DisableHTTPPrinting'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253375 (MEDIUM) Web publishing and online ordering wizards must be prevented from downloading a list of providers.
        Registry 'V-253375 (MEDIUM) Web publishing and online ordering wizards must be prevented from downloading a list of providers.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoWebServices'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253374 (MEDIUM) Downloading print driver packages over HTTP must be prevented.
        Registry 'V-253374 (MEDIUM) Downloading print driver packages over HTTP must be prevented.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName   = 'DisableWebPnPDownload'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253373 (MEDIUM) Group Policy objects must be reprocessed even if they have not changed.
        Registry 'V-253373 (MEDIUM) Group Policy objects must be reprocessed even if they have not changed.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName   = 'NoGPOListChanges'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253372 (MEDIUM) Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.
        Registry 'V-253372 (MEDIUM) Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
            ValueName   = 'DriverLoadPolicy'
            ValueType   = 'DWord'
            ValueData   = '3'
            Force       = $true
        }
        # V-253368 (MEDIUM) Windows 11 must be configured to enable Remote host allows delegation of non-exportable credentials.
        Registry 'V-253368 (MEDIUM) Windows 11 must be configured to enable Remote host allows delegation of non-exportable credentials.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName   = 'AllowProtectedCreds'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253367 (MEDIUM) Command line data must be included in process creation events.
        Registry 'V-253367 (MEDIUM) Command line data must be included in process creation events.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName   = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253366 (MEDIUM) Wi-Fi Sense must be disabled.
        Registry 'V-253366 (MEDIUM) Wi-Fi Sense must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
            ValueName   = 'AutoConnectAllowedOEM'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253365 (MEDIUM) Connections to non-domain networks when connected to a domain authenticated network must be blocked.
        Registry 'V-253365 (MEDIUM) Connections to non-domain networks when connected to a domain authenticated network must be blocked.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName   = 'fBlockNonDomain'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253364 (MEDIUM) Connections to non-domain networks when connected to a domain authenticated network must be blocked.
        Registry 'V-253364 (MEDIUM) Connections to non-domain networks when connected to a domain authenticated network must be blocked.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName   = 'fMinimizeConnections'
            ValueType   = 'DWord'
            ValueData   = '3'
            Force       = $true
        }
        # V-253363 (MEDIUM) Windows 11 must be configured to prioritize ECC Curves with longer key lengths first.
        Registry 'V-253363 (MEDIUM) Windows 11 must be configured to prioritize ECC Curves with longer key lengths first.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
            ValueName   = 'EccCurves'
            ValueType   = 'MultiString'
            ValueData   = @('NistP384', 'NistP256')
            Force       = $true
        }
        # V-253362 (MEDIUM) Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares. - NETLOGON
        Registry 'V-253362 (MEDIUM) Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares. - NETLOGON' {
            Ensure           = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName   = '\\*\NETLOGON'
            ValueType   = 'String'
            ValueData   = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            Force       = $true
        }
        # V-253362 (MEDIUM) Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares. - SYSVOL
        Registry 'V-253362 (MEDIUM) Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares. - SYSVOL' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName   = '\\*\SYSVOL'
            ValueType   = 'String'
            ValueData   = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            Force       = $true
        }
        # V-253361 (MEDIUM) Internet connection sharing must be disabled.
        Registry 'V-253361 (MEDIUM) Internet connection sharing must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_ShowSharedAccessUI'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253360 (MEDIUM) Insecure logons to an SMB server must be disabled.
        Registry 'V-253360 (MEDIUM) Insecure logons to an SMB server must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName   = 'AllowInsecureGuestAuth'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253359 (MEDIUM) Run as different user must be removed from context menus. - BAT
        Registry 'V-253359 (MEDIUM) Run as different user must be removed from context menus. - BAT' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Classes\batfile\shell\runasuser'
            ValueName   = 'SuppressionPolicy'
            ValueType   = 'DWord'
            ValueData   = '4096'
            Force       = $true
        }
        # V-253359 (MEDIUM) Run as different user must be removed from context menus. - CMD
        Registry 'V-253359 (MEDIUM) Run as different user must be removed from context menus. - CMD' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser'
            ValueName   = 'SuppressionPolicy'
            ValueType   = 'DWord'
            ValueData   = '4096'
            Force       = $true
        }
        # V-253359 (MEDIUM) Run as different user must be removed from context menus. - EXE
        Registry 'V-253359 (MEDIUM) Run as different user must be removed from context menus. - EXE' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser'
            ValueName   = 'SuppressionPolicy'
            ValueType   = 'DWord'
            ValueData   = '4096'
            Force       = $true
        }
        # V-253359 (MEDIUM) Run as different user must be removed from context menus. - MSC
        Registry 'V-253359 (MEDIUM) Run as different user must be removed from context menus. - MSC' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser'
            ValueName   = 'SuppressionPolicy'
            ValueType   = 'DWord'
            ValueData   = '4096'
            Force       = $true
        }
        # V-253358 (MEDIUM) WDigest Authentication must be disabled.
        Registry 'V-253358 (MEDIUM) WDigest Authentication must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
            ValueName   = 'UseLogonCredential'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253357 (MEDIUM) Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.
        Registry 'V-253357 (MEDIUM) Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'LocalAccountTokenFilterPolicy'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }
        # V-253356 (LOW) The system must be configured to ignore NetBIOS name release requests except from WINS servers.
        Registry 'V-253356 (LOW) The system must be configured to ignore NetBIOS name release requests except from WINS servers.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            ValueName   = 'NoNameReleaseOnDemand'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253354 (MEDIUM) The system must be configured to prevent IP source routing.
        Registry 'V-253354 (MEDIUM) The system must be configured to prevent IP source routing.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'DisableIPSourceRouting'
            ValueType   = 'DWord'
            ValueData   = '2'
            Force       = $true
        }
        # V-253353 (MEDIUM) IPv6 source routing must be configured to highest protection.
        Registry 'V-253353 (MEDIUM) IPv6 source routing must be configured to highest protection.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueName   = 'DisableIpSourceRouting'
            ValueType   = 'DWord'
            ValueData   = '2'
            Force       = $true
        }
        # V-253352 (MEDIUM) The display of slide shows on the lock screen must be disabled.
        Registry 'V-253352 (MEDIUM) The display of slide shows on the lock screen must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName   = 'NoLockScreenSlideshow'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }
        # V-253351 (MEDIUM) Windows 11 must cover or disable the built-in or attached camera when not in use.
        Registry 'V-253351 (MEDIUM) Windows 11 must cover or disable the built-in or attached camera when not in use.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
            ValueName   = 'Value'
            ValueType   = 'String'
            ValueData   = 'Deny'
            Force       = $true
        }
        # V-253350 (MEDIUM) Camera access from the lock screen must be disabled.
        Registry 'V-253350 (MEDIUM) Camera access from the lock screen must be disabled.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName   = 'NoLockScreenCamera'
            ValueType   = 'Dword'
            ValueData   = '1'
            Force       = $true
        }
        # V-253339 (MEDIUM) The System event log size must be configured to 32768 KB or greater.
        Registry 'V-253339 (MEDIUM) The System event log size must be configured to 32768 KB or greater.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName   = 'MaxSize'
            ValueType   = 'Dword'
            ValueData   = '32768'
            Force       = $true
        }
        # V-253338 (MEDIUM) The Security event log size must be configured to 1024000 KB or greater.
        Registry 'V-253338 (MEDIUM) The Security event log size must be configured to 1024000 KB or greater.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName   = 'MaxSize'
            ValueType   = 'Dword'
            ValueData   = '1024000'
            Force       = $true
        }
        # V-253337 (MEDIUM) The Application event log size must be configured to 32768 KB or greater.
        Registry 'V-253337 (MEDIUM) The Application event log size must be configured to 32768 KB or greater.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName   = 'MaxSize'
            ValueType   = 'Dword'
            ValueData   = '32768'
            Force       = $true
        }
        # V-253288 (MEDIUM) The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.
        Registry 'V-253288 (MEDIUM) The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
            ValueName   = 'Start'
            ValueType   = 'Dword'
            ValueData   = '4'
            Force       = $true
        }
        # V-253287 (MEDIUM) The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.
        Registry 'V-253287 (MEDIUM) The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName   = 'SMB1'
            ValueType   = 'Dword'
            ValueData   = '0'
            Force       = $true
        }
        SecurityOption 'V-253459 (MEDIUM) PKU2U authentication using online identities must be prevented.' {
            Name = 'NetworkSecurityPKU2U'
            #Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_Online_identities  = 'Disabled'
            #DELTA for Entra ID joined VMs
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_Online_identities  = 'Enabled'
        }
        SecurityOption 'V-253471 (MEDIUM) User Account Control must automatically deny elevation requests for standard users.' {
            Name = 'V-253471 (MEDIUM) User Account Control must automatically deny elevation requests for standard users.'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users  = 'Automatically deny elevation request'
        }        
        SecurityOption 'V-253469 (MEDIUM) User Account Control must automatically deny elevation requests for admins.' {
            Name = 'V-253469 (MEDIUM) User Account Control must automatically deny elevation requests for admins.'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode  = 'Prompt for consent on the secure desktop'
        }
        SecurityOption 'V-253468 (MEDIUM) User Account Control approval mode for the built-in Administrator must be enabled.' {
            Name = 'V-253468 (MEDIUM) User Account Control approval mode for the built-in Administrator must be enabled.'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account  = 'Enabled'
        }
        SecurityOption 'V-253447 (LOW) Caching of logon credentials must be limited.' {
            Name = 'V-253447 (LOW) Caching of logon credentials must be limited.'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = "4"
        }
        SecurityOption 'V-253452 (HIGH) Anonymous SID/Name translation must not be allowed.' {
            Name = 'V-253452 (HIGH) Anonymous SID/Name translation must not be allowed.'
            Network_access_Allow_anonymous_SID_Name_translation = "Disabled"
        }
        SecurityOption 'V-253444 (MEDIUM) The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.' {
            Name = 'V-253444 (MEDIUM) The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
            Interactive_logon_Machine_inactivity_limit = "15"
        }
        SecurityOption 'V-253443 (MEDIUM) The system must be configured to require a strong session key.' {
            Name = 'V-253443 (MEDIUM) The system must be configured to require a strong session key.'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = "Enabled"
        }
        SecurityOption 'V-253440 (MEDIUM) Outgoing secure channel traffic must be signed.' {
            Name = 'V-253440 (MEDIUM) Outgoing secure channel traffic must be signed.'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = "Enabled"
        }
        SecurityOption 'V-253439 (MEDIUM) Outgoing secure channel traffic must be encrypted.' {
            Name = 'V-253439 (MEDIUM) Outgoing secure channel traffic must be encrypted.'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = "Enabled"
        }
        SecurityOption 'V-253438 (MEDIUM) Outgoing secure channel traffic must be encrypted or signed.' {
            Name = 'V-253438 (MEDIUM) Outgoing secure channel traffic must be encrypted or signed.'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = "Enabled"
        }
        SecurityOption 'V-253437 (MEDIUM) Audit policy using subcategories must be enabled.' {
            Name = 'V-253437 (MEDIUM) Audit policy using subcategories must be enabled.'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = "Enabled"
        }
        SecurityOption 'V-253436 (MEDIUM) The built-in guest account must be renamed.' {
            Name = 'V-253436 (MEDIUM) The built-in guest account must be renamed.'
            Accounts_Rename_guest_account = "BAMNonPriv"
        }
        SecurityOption 'V-253435 (MEDIUM) The built-in administrator account must be renamed.' {
            Name = 'V-253435 (MEDIUM) The built-in administrator account must be renamed.'
            Accounts_Rename_administrator_account = "BAMPriv"
        }
        SecurityOption 'V-253434 (MEDIUM) Local accounts with blank passwords must be restricted to prevent access from the network.' {
            Name = 'V-253434 (MEDIUM) Local accounts with blank passwords must be restricted to prevent access from the network.'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = "Enabled"
        }
        SecurityOption 'V-253433 (MEDIUM) The built-in guest account must be disabled.' {
            Name = 'V-253433 (MEDIUM) The built-in guest account must be disabled.'
            Accounts_Guest_account_status = "Disabled"
        }
        # SecurityOption 'V-253432 (MEDIUM) The built-in administrator account must be disabled.' {
        #     Name = 'V-253432 (MEDIUM) The built-in administrator account must be disabled.'
        #     Accounts_Administrator_account_status = "Disabled"
        # }
    }
}

Windows11_STIG_V2R4
