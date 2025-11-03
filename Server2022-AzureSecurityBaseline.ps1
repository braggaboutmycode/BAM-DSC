# Configuration Definition
Configuration WindowsServer2022_ASB {
    param (
        [string[]]$NodeName ='localhost'
        )
 
    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc'


 
    Node $NodeName {

        ## Turn On Script Scanning
        Registry 'TurnOnScriptScanning' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueName   = 'DisableScriptScanning'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Allow Microsoft accounts to be optional
        Registry 'AllowMSFTAccountsOptional' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'MSAOptional'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Don't allow disabling Microsoft Defender Antivirus
        Registry 'DisallowDisableMDAV' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
            ValueName   = 'DisableAntiSpyware'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Prevent users from modifying exploit protection settings
        Registry 'PreventUserModifyExploitProtection' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
            ValueName   = 'DisallowExploitProtectionOverride'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Prevent Device Metadata from being accessed over internet
        Registry 'PreventDeviceMetadata' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
            ValueName   = 'PreventDeviceMetadataFromNetwork'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Disable Consumer Account State Content
        Registry 'DisableConsumerAccountState' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName   = 'DisableConsumerAccountStateContent'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Do not enumerate connected users
        Registry 'DoNotEnumerateConnectedUsers' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName   = 'DontEnumerateConnectedUsers'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Safe DLL Search Mode
        Registry 'EnableSafeDLLSearch' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName   = 'SafeDllSearchMode'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Do not apply during periodic background processing registry policy
        Registry 'RegistryPolicyBackgroundRefresh' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName   = 'NoBackgroundPolicy'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Turn off background refresh of Group Policy
        Registry 'DontTurnOffGPOBackgroundRefresh' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'DisableBkGndGroupPolicy'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## NetBT NodeType Configuration
        Registry 'NetBTNodeConfig' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName   = 'NodeType'
            ValueType   = 'DWord'
            ValueData   = '2'
        }
        ## Don't allow input personalization
        Registry 'InputPersonalization' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName   = 'AllowInputPersonalization'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Block user from showing account details on sign-in
        Registry 'BlockShowingAccountDetailsOnSignIn' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName   = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Configure Solicited Remote Assistance
        Registry 'BlockSolicitedRemoteAssistance' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fAllowToGetHelp'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Do not display the password reveal button
        Registry 'DontDisplayPasswordRevealButton' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI'
            ValueName   = 'DisablePasswordReveal'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
        Registry 'TurnOffInternetConnectionWizard' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName   = 'ExitOnMSICW'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Limits print driver installation to administrators
        Registry 'LimitPrintDriverInstallation' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            ValueName   = 'RestrictDriverInstallationToAdministrators'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Security Event Percentage Threshold
        Registry 'SecurityEventThreshold' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
            ValueName   = 'WarningLevel'
            ValueType   = 'DWord'
            ValueData   = '90'
        }
        ## Configured "Do not show feedback notifications"
        Registry 'FeedbackNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'DoNotShowFeedbackNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Prohibit use of Internet Connection Sharing on your DNS domain network
        Registry 'ProhibitICSonDNS' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_ShowSharedAccessUI'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Disable App Screen Notifications on lock screen
        Registry 'DisableLockScreenAppNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'DisableLockScreenAppNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Turn off multicast name resolution
        Registry 'TurnOffMulticastNameResolution' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName   = 'EnableMulticast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Prohibit install on network bridge on DNS domain network
        Registry 'ProhibitInstallNetworkBridge' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_AllowNetBridge_NLA'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Enable RPC Endpoint Mapper Client Authentication 
        Registry 'EnableRPCEndpointMapperClient' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName   = 'EnableAuthEpResolution'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Setup: Specify the maximum log file size (KB)
        Registry 'SetupLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName   = 'MaxSize'
            ValueType   = 'DWord'
            ValueData   = '32768'
        }

        ## Behavior of the elvation prompt for admins in admin approval mode
        Registry 'AdminApprovalModeforAdmins' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'ConsentPromptBehaviorAdmin'
            ValueType   = 'DWord'
            ValueData   = '2'
            Force       = $true
        }
        ## Enable Domain Firewall
        Registry 'EnableDomainFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Apply Local Connection Security Rules
        Registry 'ApplyLocalConnectionSecurityDomainFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Allow Outbound Connections DomainFW
        Registry 'AllowOutboundConnectionsDomainFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Enable Domain Firewall Unicast Response
        Registry 'AllowUnicastResponsesDomainFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Allow Inbound Connections DomainFW
        Registry 'AllowOInboundConnectionsDomainFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DefaultInboundAction'
            ValueType   = 'DWord'
            ValueData   = '1'
        }        
        # Domain Firewall Logging Name
        Registry 'DomainFirewallLoggingName' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogFilePath'
            ValueType   = 'String'
            ValueData   = '%SystemRoot%\System32\logfiles\firewall\domainfw.log'
        }
        ## Domain Firewall Log Dropped Packets
        Registry 'DomainFirewallLogDropped' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogDroppedPackets'
            ValueType   = 'DWord'
            ValueData   = '1'
        }        
        # Domain Firewall Log Sucessful Connections
        Registry 'DomainFirewallLogSuccess' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogSuccessfulConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }   
        ## Domain Firewall Log Size
        Registry 'DomainFirewallLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }        
        ## Disabled Domain Firewall Display Notifications
        Registry 'DisableDomainFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Private Firewall
        Registry 'EnablePrivateFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Apply Local Connection Security Rules
        Registry 'ApplyLocalConnectionSecurityPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Allow Outbound Connections PrivateFW
        Registry 'AllowOutboundConnectionsPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Allow Inbound Connections PrivateFW
        Registry 'AllowOInboundConnectionsPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DefaultInboundAction'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Private Firewall Unicast Response
        Registry 'AllowUnicastResponsesPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }        
        # Private Firewall Logging Name
        Registry 'PrivateFirewallLoggingName' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName   = 'LogFilePath'
            ValueType   = 'String'
            ValueData   = '%SystemRoot%\System32\logfiles\firewall\privatefw.log'
        }
        ## Private Firewall Log Dropped Packets
        Registry 'PrivateFirewallLogDropped' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
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
        ## Private Firewall Log Size
        Registry 'PrivateFirewallLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }
        ## Disabled Private Firewall Display Notifications
        Registry 'DisablePrivateFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Public Firewall
        Registry 'EnablePublicFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Apply Local Connection Security Rules
        Registry 'ApplyLocalConnectionSecurityPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Allow Outbound Connections PublicFW
        Registry 'AllowOutboundConnectionsPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        } 
        ## Allow Inbound Connections PublicFW
        Registry 'AllowInboundConnectionsPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DefaultInboundAction'
            ValueType   = 'DWord'
            ValueData   = '1'
        }        
        # Public Firewall Logging Name
        Registry 'PublicFirewallLoggingName' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogFilePath'
            ValueType   = 'String'
            ValueData   = '%SystemRoot%\System32\logfiles\firewall\publicfw.log'
        }
        ## Public Firewall Log Dropped Packets
        Registry 'PublicFirewallLogDropped' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogDroppedPackets'
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
        ## Public Firewall Log Size
        Registry 'PublicFirewallLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }
        ## Disabled Public Firewall Display Notifications
        Registry 'DisablePublicFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Set DNS for Web Authentication
        Registry 'SetDNSContextWebAuth' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'NV Domain'
            ValueType   = 'String'
            ValueData   = 'domainname.com'
            Force       = $true
        }
        ## Increase a process working set
        UserRightsAssignment IncreaseProcessWorkingSet {
            Policy       = 'Increase_a_process_working_set'
            Identity     = @('Administrators','LOCAL SERVICE')
            Force        = $true
        }
        ## Bypass Traverse Checking
        UserRightsAssignment Bypasstraversechecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = @('Administrators','Authenticated Users','Backup Operators','LOCAL SERVICE','NETWORK SERVICE')
            Force        = $true
        }
        # 2.2.18 (L1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
            Force        = $true
        }
        # 2.2.18 (L1) Ensure 'Deny log on through RDP to include 'Guests'
        UserRightsAssignment DenylogonthroughRDP {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
            Force        = $true
        }
        # 2.2.18 (L1) Ensure 'Deny log on through RDP to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
            Force        = $true
        }
        UserRightsAssignment Denyaccessfromnetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests'
            Force        = $true
        }
        # 2.2.18 (L1) Ensure 'Deny log on through RDP to include 'Guests'
        UserRightsAssignment AccessFromRDP {
            Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity     = @('Administrators','Remote Desktop Users')
            Force        = $true
        }
        UserRightsAssignment AccessLocally {
            Policy       = 'Allow_log_on_locally'
            Identity     = 'Administrators'
            Force        = $true
        }
        UserRightsAssignment AccessfromNetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = @('Administrators','Authenticated Users')
            Force        = $true
        }

        SecurityOption AccountSecurityOptions {
            Name = 'AccountSecurityOptions'
        # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Enabled'  to allow Azure authentication
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities  = 'Enabled'
        ## Determins wheter digital certificates are processed when software restriction policies are enabled and a user or process attempts to run software with an .exe file name extension
            System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'
        ## Do not display last username
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
        #Message Title
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'Logon Consent Banner'
        #SPNValidation
            Microsoft_network_server_Server_SPN_target_name_validation_level = 'Accept if provided by client'
        ##Rename Guest Account
            Accounts_Rename_guest_account = 'abcguest'
        }
        
        AuditPolicySubcategory DetailedFileShareFailure
        {
            Name      = 'Detailed File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory OtherPolicyChangeFailure
        {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory FileShareSuccess
        {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory FileShareFailure
        {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

}
}

WindowsServer2022_ASB
