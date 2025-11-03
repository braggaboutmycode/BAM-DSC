# Configuration Definition
Configuration Windows11_ASB {
    param (
        [string[]]$NodeName ='localhost'
        )
 
    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc'
 
    Node $NodeName {
        AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24
            # 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 60
            # 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 1
            # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14
            # 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            # 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 3
        }

        # Ensure 'Windows Search (WSearch)' is set to 'Disabled'
        Registry 'Wsearch' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Services\Wsearch'
            ValueName   = 'Start'
            ValueType   = 'DWord'
            ValueData   = '4'
        }
        # Configured "Allow Diagnostics Data" is set to '1' which mean, send only basic amount of diagnostic data
        Registry 'AllowTelemetry' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Ensure 'Boot-Start Driver Initialization Policy' is set to 3 which means it will enable Good, unknown and bad but critical drivers
        Registry 'Boot-StartDriver' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
            ValueName   = 'DriverLoadPolicy'
            ValueType   = 'DWord'
            ValueData   = '3'
        }
        # Configured "Do not show feedback notifications"
        Registry 'FeedbackNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'DoNotShowFeedbackNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disable App Screen Notifications on lock screen
        Registry 'DisableLockScreenAppNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'DisableLockScreenAppNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Enable Domain Firewall
        Registry 'EnableDomainFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Enable Private Firewall
        Registry 'EnablePrivateFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Enable Private Firewall Unicast Response
        Registry 'AllowUnicastResponsesPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Apply Local Connection Security Rules
        Registry 'ApplyLocalConnectionSecurityPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Allow Outbound Connections PrivateFW
        Registry 'AllowOutboundConnectionsPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Enable Public Firewall
        Registry 'EnablePublicFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disable Public Firewall Unicast Response
        Registry 'DisableUnicastResponsesPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Allow Outbound Connections PublicFW
        Registry 'AllowOutboundConnectionsPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Disabled Private Firewall Display Notifications
        Registry 'DisablePrivateFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disabled Public Firewall Display Notifications
        Registry 'DisablePublicFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Domain Firewall Log Dropped Packets
        Registry 'DomainFirewallLogDropped' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogDroppedPackets'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Private Firewall Log Sucessful Connections
        Registry 'PrivateFirewallLogSuccess' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName   = 'LogSuccessfulConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Public Firewall Log Sucessful Connections
        Registry 'PublicFirewallLogSuccess' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogSuccessfulConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Public Firewall Log Size
        Registry 'PublicFirewallLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }
        # Behavior of the elvation prompt for admins in admin approval mode
        Registry 'AdminApprovalModeforAdmins' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'ConsentPromptBehaviorAdmin'
            ValueType   = 'DWord'
            ValueData   = '2'
        }
        # Don't display network selection UI
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'DontDisplayNetworkSelectionUI'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disallow AutoPlay for non-volume
        Registry 'DisallowAutoPlayforNonVolume' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName   = 'NoAutoplayfornonVolume'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Turn Off AutoPlay
        Registry 'TurnOffAutoPlay' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoDriveTypeAutoRun'
            ValueType   = 'DWord'
            ValueData   = '255'
        }
        # Set the Default Behavior for Autorun
        Registry 'SetDefaultAutoRunBehavior' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoAutorun'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disable downloading print drivers of HTTP
        Registry 'DisableDownloadPrintDriversHTTP' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName   = 'DisableWebPnPDownload'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Sign-in last interactive user automatically after a system-initiatied restart
        Registry 'DisableSignInLastUserAfterRestart' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'DisableAutomaticRestartSignOn'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Prohibit install on network bridge on DNS domain network
        Registry 'ProhibitInstallNetworkBridge' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_AllowNetBridge_NLA'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Windows Server must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.
        Registry 'PreventICMPredirectsfromOSPF' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'EnableICMPRedirect'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Set Defender Samples MAPS consent
        Registry 'SendMAPSSafeSamplesConsent' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet'
            ValueName   = 'SubmitSamplesConsent'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Sets the PKU2U setting to Not Set so that it doesn't show up in the Azure Security Baseline Guest Configuration
        Registry 'PKU2UNotSet' {
            Ensure      = 'Absent'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'
            ValueName   = 'AllowOnlineID'
        }
        # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
        AuditPolicySubcategory "Audit Credential Validation (Success)"
        {
            Name      = 'Credential Validation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # 2.2.17 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
        }
        # Ensure 'Deny log on locally to include 'Guests'
        UserRightsAssignment Denylogonaslocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
        }
        # 2.2.18 (L1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
        }
        # 2.2.20 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
        }
        # 2.2.16 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests'
        }
        # 2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Windows Manager\Windows Manager Group'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators'
            Force        = $true
        }
        # Increase a process working set
        UserRightsAssignment IncreaseProcessWorkingSet {
            Policy       = 'Increase_a_process_working_set'
            Identity     = @('Administrators','LOCAL SERVICE')
            Force        = $true
        }
        # Increase a process working set
        UserRightsAssignment Bypasstraversechecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = @('Administrators','Authenticated Users','Backup Operators','LOCAL SERVICE','NETWORK SERVICE')
            Force        = $true
        }
        # Allow Log On Locally to only admins
        UserRightsAssignment AllowLogOnLocally {
            Policy       = 'Allow_log_on_locally'
            Identity     = 'Administrators'
            Force        = $true
        }
        #Allow access from the network
        UserRightsAssignment AllowLogOnNetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = @('Administrators','Authenticated Users')
            Force        = $true
        }
        SecurityOption AccountSecurityOptions {
            Name = 'AccountSecurityOptions'
        # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Enabled'  to allow Azure authentication
            #Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities  = 'Enabled'
        # Require Admin Approval mode for Built In Admins
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account  = 'Enabled'
        # Determins wheter digital certificates are processed when software restriction policies are enabled and a user or process attempts to run software with an .exe file name extension
            System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'
        # Determines wheter users can use private keys, such as their Secure/Multipurpose Internet Mail Extensions (S/MIME) key, without a password
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        # Number of logons to cache
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = "4"
        }
}
}

Windows11_ASB
