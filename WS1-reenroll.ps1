# WS1-Enroll
# Version 3.0 - 10/05/2023 - Primera version publica


#-----------------PSADT Function "QueryUser" from AppDeployToolkitMain.cs file------------------------------------
# https://github.com/PSAppDeployToolkit/PSAppDeployToolkit/tree/master/Toolkit/AppDeployToolkit
#-----------------------------------------------------------------------------------------------------------------
$code = @"
using System;
using System.Text;
using System.Collections;
using System.ComponentModel;
using System.DirectoryServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
public class QueryUser
	{
		[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern IntPtr WTSOpenServer(string pServerName);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern void WTSCloseServer(IntPtr hServer);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
		public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr pBuffer, out int pBytesReturned);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
		public static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr pSessionInfo, out int pCount);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern void WTSFreeMemory(IntPtr pMemory);
		
		[DllImport("winsta.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern int WinStationQueryInformation(IntPtr hServer, int sessionId, int information, ref WINSTATIONINFORMATIONW pBuffer, int bufferLength, ref int returnedLength);
		
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern int GetCurrentProcessId();
		
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern bool ProcessIdToSessionId(int processId, ref int pSessionId);
		
		public class TerminalSessionData
		{
			public int SessionId;
			public string ConnectionState;
			public string SessionName;
			public bool IsUserSession;
			public TerminalSessionData(int sessionId, string connState, string sessionName, bool isUserSession)
			{
				SessionId = sessionId;
				ConnectionState = connState;
				SessionName = sessionName;
				IsUserSession = isUserSession;
			}
		}
		
		public class TerminalSessionInfo
		{
			public string NTAccount;
			public string SID;
			public string UserName;
			public string DomainName;
			public int SessionId;
			public string SessionName;
			public string ConnectState;
			public bool IsCurrentSession;
			public bool IsConsoleSession;
			public bool IsActiveUserSession;
			public bool IsUserSession;
			public bool IsRdpSession;
			public bool IsLocalAdmin;
			public DateTime? LogonTime;
			public TimeSpan? IdleTime;
			public DateTime? DisconnectTime;
			public string ClientName;
			public string ClientProtocolType;
			public string ClientDirectory;
			public int ClientBuildNumber;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		private struct WTS_SESSION_INFO
		{
			public Int32 SessionId;
			[MarshalAs(UnmanagedType.LPStr)]
			public string SessionName;
			public WTS_CONNECTSTATE_CLASS State;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct WINSTATIONINFORMATIONW
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 70)]
			private byte[] Reserved1;
			public int SessionId;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			private byte[] Reserved2;
			public FILETIME ConnectTime;
			public FILETIME DisconnectTime;
			public FILETIME LastInputTime;
			public FILETIME LoginTime;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1096)]
			private byte[] Reserved3;
			public FILETIME CurrentTime;
		}
		
		public enum WINSTATIONINFOCLASS
		{
			WinStationInformation = 8
		}
		
		public enum WTS_CONNECTSTATE_CLASS
		{
			Active,
			Connected,
			ConnectQuery,
			Shadow,
			Disconnected,
			Idle,
			Listen,
			Reset,
			Down,
			Init
		}
		
		public enum WTS_INFO_CLASS
		{
			SessionId=4,
			UserName,
			SessionName,
			DomainName,
			ConnectState,
			ClientBuildNumber,
			ClientName,
			ClientDirectory,
			ClientProtocolType=16
		}
		
		private static IntPtr OpenServer(string Name)
		{
			IntPtr server = WTSOpenServer(Name);
			return server;
		}
		
		private static void CloseServer(IntPtr ServerHandle)
		{
			WTSCloseServer(ServerHandle);
		}
		
		private static IList<T> PtrToStructureList<T>(IntPtr ppList, int count) where T : struct
		{
			List<T> result = new List<T>();
			long pointer = ppList.ToInt64();
			int sizeOf = Marshal.SizeOf(typeof(T));
			
			for (int index = 0; index < count; index++)
			{
				T item = (T) Marshal.PtrToStructure(new IntPtr(pointer), typeof(T));
				result.Add(item);
				pointer += sizeOf;
			}
			return result;
		}
		
		public static DateTime? FileTimeToDateTime(FILETIME ft)
		{
			if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0)
			{
				return null;
			}
			long hFT = (((long) ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
			return DateTime.FromFileTime(hFT);
		}
		
		public static WINSTATIONINFORMATIONW GetWinStationInformation(IntPtr server, int sessionId)
		{
			int retLen = 0;
			WINSTATIONINFORMATIONW wsInfo = new WINSTATIONINFORMATIONW();
			WinStationQueryInformation(server, sessionId, (int) WINSTATIONINFOCLASS.WinStationInformation, ref wsInfo, Marshal.SizeOf(typeof(WINSTATIONINFORMATIONW)), ref retLen);
			return wsInfo;
		}
		
		public static TerminalSessionData[] ListSessions(string ServerName)
		{
			IntPtr server = IntPtr.Zero;
			if (ServerName == "localhost" || ServerName == String.Empty)
			{
				ServerName = Environment.MachineName;
			}
			
			List<TerminalSessionData> results = new List<TerminalSessionData>();
			
			try
			{
				server = OpenServer(ServerName);
				IntPtr ppSessionInfo = IntPtr.Zero;
				int count;
				bool _isUserSession = false;
				IList<WTS_SESSION_INFO> sessionsInfo;
				
				if (WTSEnumerateSessions(server, 0, 1, out ppSessionInfo, out count) == 0)
				{
					throw new Win32Exception();
				}
				
				try
				{
					sessionsInfo = PtrToStructureList<WTS_SESSION_INFO>(ppSessionInfo, count);
				}
				finally
				{
					WTSFreeMemory(ppSessionInfo);
				}
				
				foreach (WTS_SESSION_INFO sessionInfo in sessionsInfo)
				{
					if (sessionInfo.SessionName != "Services" && sessionInfo.SessionName != "RDP-Tcp")
					{
						_isUserSession = true;
					}
					results.Add(new TerminalSessionData(sessionInfo.SessionId, sessionInfo.State.ToString(), sessionInfo.SessionName, _isUserSession));
					_isUserSession = false;
				}
			}
			finally
			{
				CloseServer(server);
			}
			
			TerminalSessionData[] returnData = results.ToArray();
			return returnData;
		}
		
		public static TerminalSessionInfo GetSessionInfo(string ServerName, int SessionId)
		{
			IntPtr server = IntPtr.Zero;
			IntPtr buffer = IntPtr.Zero;
			int bytesReturned;
			TerminalSessionInfo data = new TerminalSessionInfo();
			bool _IsCurrentSessionId = false;
			bool _IsConsoleSession = false;
			bool _IsUserSession = false;
			int currentSessionID = 0;
			string _NTAccount = String.Empty;
			if (ServerName == "localhost" || ServerName == String.Empty)
			{
				ServerName = Environment.MachineName;
			}
			if (ProcessIdToSessionId(GetCurrentProcessId(), ref currentSessionID) == false)
			{
				currentSessionID = -1;
			}
			
			// Get all members of the local administrators group
			bool _IsLocalAdminCheckSuccess = false;
			List<string> localAdminGroupSidsList = new List<string>();
			try
			{
				DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + ServerName + ",Computer");
				string localAdminGroupName = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\')[1];
				DirectoryEntry admGroup = localMachine.Children.Find(localAdminGroupName, "group");
				object members = admGroup.Invoke("members", null);
				string validSidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
				foreach (object groupMember in (IEnumerable)members)
				{
					DirectoryEntry member = new DirectoryEntry(groupMember);
					if (member.Name != String.Empty)
					{
						if (Regex.IsMatch(member.Name, validSidPattern))
						{
							localAdminGroupSidsList.Add(member.Name);
						}
						else
						{
							localAdminGroupSidsList.Add((new NTAccount(member.Name)).Translate(typeof(SecurityIdentifier)).Value);
						}
					}
				}
				_IsLocalAdminCheckSuccess = true;
			}
			catch { }
			
			try
			{
				server = OpenServer(ServerName);
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientBuildNumber, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				int lData = Marshal.ReadInt32(buffer);
				data.ClientBuildNumber = lData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientDirectory, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				string strData = Marshal.PtrToStringAnsi(buffer);
				data.ClientDirectory = strData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer);
				data.ClientName = strData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientProtocolType, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				Int16 intData = Marshal.ReadInt16(buffer);
				if (intData == 2)
				{
					strData = "RDP";
					data.IsRdpSession = true;
				}
				else
				{
					strData = "";
					data.IsRdpSession = false;
				}
				data.ClientProtocolType = strData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ConnectState, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				lData = Marshal.ReadInt32(buffer);
				data.ConnectState = ((WTS_CONNECTSTATE_CLASS) lData).ToString();
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionId, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				lData = Marshal.ReadInt32(buffer);
				data.SessionId = lData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.DomainName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer).ToUpper();
				data.DomainName = strData;
				if (strData != String.Empty)
				{
					_NTAccount = strData;
				}
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.UserName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer);
				data.UserName = strData;
				if (strData != String.Empty)
				{
					data.NTAccount = _NTAccount + "\\" + strData;
					string _Sid = (new NTAccount(_NTAccount + "\\" + strData)).Translate(typeof(SecurityIdentifier)).Value;
					data.SID = _Sid;
					if (_IsLocalAdminCheckSuccess == true)
					{
						foreach (string localAdminGroupSid in localAdminGroupSidsList)
						{
							if (localAdminGroupSid == _Sid)
							{
								data.IsLocalAdmin = true;
								break;
							}
							else
							{
								data.IsLocalAdmin = false;
							}
						}
					}
				}
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer);
				data.SessionName = strData;
				if (strData != "Services" && strData != "RDP-Tcp" && data.UserName != String.Empty)
				{
					_IsUserSession = true;
				}
				data.IsUserSession = _IsUserSession;
				if (strData == "Console")
				{
					_IsConsoleSession = true;
				}
				data.IsConsoleSession = _IsConsoleSession;
				
				WINSTATIONINFORMATIONW wsInfo = GetWinStationInformation(server, SessionId);
				DateTime? _loginTime = FileTimeToDateTime(wsInfo.LoginTime);
				DateTime? _lastInputTime = FileTimeToDateTime(wsInfo.LastInputTime);
				DateTime? _disconnectTime = FileTimeToDateTime(wsInfo.DisconnectTime);
				DateTime? _currentTime = FileTimeToDateTime(wsInfo.CurrentTime);
				TimeSpan? _idleTime = (_currentTime != null && _lastInputTime != null) ? _currentTime.Value - _lastInputTime.Value : TimeSpan.Zero;
				data.LogonTime = _loginTime;
				data.IdleTime = _idleTime;
				data.DisconnectTime = _disconnectTime;
				
				if (currentSessionID == SessionId)
				{
					_IsCurrentSessionId = true;
				}
				data.IsCurrentSession = _IsCurrentSessionId;
			}
			finally
			{
				WTSFreeMemory(buffer);
				buffer = IntPtr.Zero;
				CloseServer(server);
			}
			return data;
		}
		
		public static TerminalSessionInfo[] GetUserSessionInfo(string ServerName)
		{
			if (ServerName == "localhost" || ServerName == String.Empty)
			{
				ServerName = Environment.MachineName;
			}
			
			// Find and get detailed information for all user sessions
			// Also determine the active user session. If a console user exists, then that will be the active user session.
			// If no console user exists but users are logged in, such as on terminal servers, then select the first logged-in non-console user that is either 'Active' or 'Connected' as the active user.
			TerminalSessionData[] sessions = ListSessions(ServerName);
			TerminalSessionInfo sessionInfo = new TerminalSessionInfo();
			List<TerminalSessionInfo> userSessionsInfo = new List<TerminalSessionInfo>();
			string firstActiveUserNTAccount = String.Empty;
			bool IsActiveUserSessionSet = false;
			foreach (TerminalSessionData session in sessions)
			{
				if (session.IsUserSession == true)
				{
					sessionInfo = GetSessionInfo(ServerName, session.SessionId);
					if (sessionInfo.IsUserSession == true)
					{
						if ((firstActiveUserNTAccount == String.Empty) && (sessionInfo.ConnectState == "Active" || sessionInfo.ConnectState == "Connected"))
						{
							firstActiveUserNTAccount = sessionInfo.NTAccount;
						}
						
						if (sessionInfo.IsConsoleSession == true)
						{
							sessionInfo.IsActiveUserSession = true;
							IsActiveUserSessionSet = true;
						}
						else
						{
							sessionInfo.IsActiveUserSession = false;
						}
						
						userSessionsInfo.Add(sessionInfo);
					}
				}
			}
			
			TerminalSessionInfo[] userSessions = userSessionsInfo.ToArray();
			if (IsActiveUserSessionSet == false)
			{
				foreach (TerminalSessionInfo userSession in userSessions)
				{
					if (userSession.NTAccount == firstActiveUserNTAccount)
					{
						userSession.IsActiveUserSession = true;
						break;
					}
				}
			}
			
			return userSessions;
		}
	}
"@

[string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $code -Language CSharp	-IgnoreWarnings -ErrorAction 'Stop'

#------------------------------------------------------------------------
Timeout /T 60
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
#Variable Section
$silent = $false
$version = 'v3.0'
$server = "ds.emm.gob.es"
$user = [QueryUser]::GetUserSessionInfo($env:COMPUTERNAME)
$userFullname = "{0}\{1}" -f $user.DomainName, $user.UserName
$oUser = New-Object -TypeName System.Security.Principal.NTAccount($userFullname)
$global:SID = $oUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
$scriptfilename = "WS1-Enroll.ps1.log" #local log file name
$current_path = $PSScriptRoot;
#$current_path="C:\Temp\Products"
if ($PSScriptRoot -eq "") {
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $Logpath = "C:\Reasign\";
}
else {
    $Logpath = $PSScriptRoot
}
#   $Logpath = "C:\Temp\Products";

$logfile = "$logpath\$scriptfilename"
$AgentPath = "$logpath\AirwatchAgent.msi"
$VarsPath = "$logpath\vars.txt"


#End of Variable Section
#------------------------------------------------------------------------
#functions
Function Write-Log {
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Message
		
    )
	
    $date = $date = (Get-Date).ToString("dd-M-yyy hh:mm")
    "$date | $Message" | Out-File -Append $LogFile
    Write-Host $Message
}

Function Uninstall-Hub {
    write-log "Attempting to remove Intelligent HUB and MDM Enrollment"
    write-log "Checking for existing Airwatch/Workspace One Hub installations"

    $location = @()
    $location += (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object { $_.DisplayName -like "Airwatch*" -or $_.DisplayName -like "Workspace ONE Intelligent Hub*" })
    $location += (Get-ItemProperty HKLM:\Software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object { $_.DisplayName -like "Airwatch*" -or $_.DisplayName -like "Workspace ONE Intelligent Hub*" })
    $array = @()

    $array = foreach ($item in $location) {
        $Object = New-Object psobject
        $Object | Add-Member -MemberType NoteProperty -Name DisplayName -Value $item.DisplayName
        $Object | Add-Member -MemberType NoteProperty -Name GUID -Value $item.PSChildname
        $Object | Add-Member -MemberType NoteProperty -Name DisplayVersion -Value $item.DisplayVersion
        $object
    }
    $array

    foreach ($item in $array) {
        Try {		
            Write-Log "$($item.DisplayName) version $($item.DisplayVersion) found, uninstalling."
            start-process -Wait "msiexec" -arg "/X $($item.GUID) /qn /norestart"
            Start-Sleep -Seconds 10
            Write-Log "Uninstall SFD Agent legacy versions"
            start-process -Wait "msiexec" -arg "/X {4754DA99-2E70-43E7-A075-A45157FD87D3} /qn /norestart"
            start-process -Wait "msiexec" -arg "/X {EA3F660D-22B7-475F-A15B-A322CC519EE9} /qn /norestart"
            start-process -Wait "msiexec" -arg "/X {A825F4AA-4E41-45F7-AEB2-0205E90F8CCD} /qn /norestart"			
			
            Start-Sleep -Seconds 10
        }
        catch {
            Write-Log $_.Exception
        }
		
    }
    Write-Log  "Remove the legacy WS1 App catalog"
    $packageName = "AirWatchLLC.VMwareWorkspaceONE"
    Get-AppxPackage  $packageName | Remove-AppxPackage -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5


    #Delete reg keys
    Write-Log  "Remove registry keys"
    Remove-Item -Path HKLM:\SOFTWARE\Airwatch -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\AirwatchMDM -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\* -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\omadm\Accounts\* -Recurse -ErrorAction SilentlyContinue


    Write-Log "Syncing oma-dm to ensure that it breaks mdm relationship after hub removal"
    $GUID = (Get-Item -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue).PSChildname
    Start-Process "$ENV:windir\system32\DeviceEnroller.exe" -arg "/o $GUID /c"
    write-log "Wait 5 min for OMA-DM Un-enrollment to complete"
    Start-Sleep 300
	
    #Delete reg keys (again)
    Write-Log  "Making sure there is no registry keys left"
    Remove-Item -Path HKLM:\SOFTWARE\Airwatch -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\AirwatchMDM -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\* -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\omadm\Accounts\* -Recurse -ErrorAction SilentlyContinue

    #Delete log folders
    Write-Log  "Remove Log files and folders"
    $path = "$env:ProgramData\AirWatch\"
    Get-ChildItem $path -Recurse | Remove-Item -Recurse -Force  -ErrorAction SilentlyContinue
    Start-Sleep 5
    Remove-Item -Recurse -Force  -ErrorAction SilentlyContinue -path $path

    $pathMDM = "$env:ProgramData\AirWatchMDM\"
    if (Get-Item "$($pathmdm)Apps" -ErrorAction SilentlyContinue) {	(Get-Item "$($pathmdm)Apps").Delete() }
    Get-ChildItem $pathMDM -Recurse | Remove-Item -Recurse -Force  -ErrorAction SilentlyContinue
    Start-Sleep 5
    if (Get-Item "$($pathmdm)Apps" -ErrorAction SilentlyContinue) {	(Get-Item "$($pathmdm)Apps").Delete() }
    Remove-Item -Recurse -Force  -ErrorAction SilentlyContinue -path $pathMDM

    $pathSFD = "$env:ProgramData\VMware\SfdAgent\"
    Get-ChildItem $pathSFD -Recurse | Remove-Item -Recurse -Force  -ErrorAction SilentlyContinue
    Start-Sleep 5	
    Remove-Item -Recurse -Force  -ErrorAction SilentlyContinue -path $pathSFD

    #Write-Log  "Making sure there is no files and folders left (might raise an error)"
    #Remove-Item -Path HKLM:\SOFTWARE\Airwatch -Recurse -ErrorAction SilentlyContinue
    #Remove-Item -Path HKLM:\SOFTWARE\AirwatchMDM -Recurse -ErrorAction SilentlyContinue
    Start-Sleep 100

    #delete Airwatch certificates
    Write-Log  "Remove Airwatch certificates"
    $Certs = get-childitem cert:"CurrentUser" -Recurse
    $AirwatchCert = $certs | Where-Object { $_.Issuer -eq "CN=AirWatchCa" }
    foreach ($Cert in $AirwatchCert) {
        $cert | Remove-Item -Force
    }
    $AirwatchCert = $certs | Where-Object { $_.Subject -like "*AwDeviceRoot*" }
    foreach ($Cert in $AirwatchCert) {
        $cert | Remove-Item -Force
    }
}


Function Enroll-Hub {
    write-log "Enrolling Workspace ONE Hub with the following parameters: Server= $server, Organization Group ID= $LGName, Staging Username: $UPN / $Username, Staging Password: ******, AssignToLoggedInUser=Y"

    $msiargumentlist = "/i $AgentPath /quiet ENROLL=Y SERVER=$Server LGNAME=$LGName USERNAME=$Username PASSWORD=$Password DOWNLOADWSBUNDLE=FALSE ASSIGNTOLOGGEDINUSER=Y /log $Logpath\Awagent.log"
    Start-Process msiexec.exe -Wait -ArgumentList $msiargumentlist
    write-log "Waiting 5 min for WS1 enrollment to complete the process..."

    start-sleep 300

	
}


function Get-Enrollment {

    #Getting GUID from MDM Enrollment
    Write-Log "Checking for valid Workspace ONE Enrollment..."
    $val = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue).PSChildname
	
    $mdm = $false
    foreach ($row in $val) { #loops through in case of more than one GUID on the system
		
        $PATH2 = "HKLM:\SOFTWARE\Microsoft\Enrollments\$row"
        $upn = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).UPN
        $EnrollmentState = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).EnrollmentState
        $providerID = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).ProviderID
		
		
        if ($EnrollmentState -eq "1" -and $upn -and $providerID -eq "AirWatchMDM") {
            $mdm = $True
            $guid = $row
        }

    }
    if ($mdm) {
        $server = (Get-ItemProperty -Path "HKLM:\SOFTWARE\AIRWATCH\BEACON\CONSOLE SETTINGS").Server
		
        $Object = New-Object psobject
        $Object | Add-Member -MemberType NoteProperty -Name UPN -Value $UPN
        $Object | Add-Member -MemberType NoteProperty -Name GUID -Value $GUID
        $Object | Add-Member -MemberType NoteProperty -Name Server -Value $server
        Write-Log "Workspace ONE Enrollment found. Enrolled user: $UPN. Enrolled Server: $server"
        return $Object
    }
    else {
        Write-Log "No Workspace ONE Enrollment found."
        return $false
    }
}


function Check-agent {
    if (!(Test-Path $AgentPath)) {
        Write-Log "Unable to find AirwatchAgent.msi file in expected location."
        exit 1
    }
    else {
        Write-Log "Verified AirwatchAgent.msi file"	
    }
	
}

function Check-variables {
    if (!(Test-Path $VarsPath)) {
        Write-Log "Unable to find vars.txt file in expected location."
        exit 1
    }
    else {
        Write-Log "Verified vars.txt file"	
    }
	
}

function disable-notifications {
    write-log "Silent: Disabling Windows Toast notification for Device Enrollment Activity for user $global:SID"
    New-Item -Path Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity -Name "Enabled" -Type DWord -Value 0 -Force
    Write-Log "Silent: HKEY User's Registry for DeviceEnrollmentActivity is set to disable notification"      
}

function enable-notifications {
    Write-Log "Silent: Enabling Windows Toast notification for Device Enrollment Activity for user $global:SID"
    # New-Item -Path Registry::HKEY_USERS\$global:SID\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path Registry::HKEY_USERS\$global:SID\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity -Name "Enabled" -ErrorAction SilentlyContinue -Force
    Write-Log "Silent: HKEY User's Registry for DeviceEnrollmentActivity is set to enable notification" 
}


#--------------------------MAIN--------------------------#
write-log "Script version is: $version"
Write-Log "Airwatch Agent path: $AgentPath"
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch as an elevated process:
    Write-Log "Script is not run with elevated permissions. Please re-run elevated."
    Pause
    exit
}
#Ensuring log locations exist
If ((Test-Path $Logpath) -eq $false) {
    mkdir -Path $Logpath -ErrorAction SilentlyContinue
}
$Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables["PROCESSOR_ARCHITECTURE"];
if ($Arch -eq 'x86') {
    Write-log 'Running 32-bit PowerShell, please re-run in 64 bit powershell context.'
    exit 1
}
elseif ($Arch -ne 'amd64') {
    Write-log 'Running 64-bit PowerShell'
}

#Checking connection to target server before doing anything else
Write-Log "Verifying connection to the target UEM server: $server"
$connectionStatus = Test-NetConnection -ComputerName $server -Port 443  -InformationLevel Quiet
if ($connectionStatus) {
    Write-Log "Test connection passed."

}
else {
    Write-Log "Connection failed to $server. Exiting script. "
    exit 1
}



if (!(Test-Path $VarsPath)) {
    Write-Log "Unable to find vars.txt file in expected location."
    exit 1
}
else {
    Write-Log "Verified vars.txt file"	
    Get-Content "$logpath\vars.txt" | Foreach-Object {
        $var = $_.Split('=')
        New-Variable -Name $var[0] -Value $var[1]
    }
}

if ($silent) {
    disable-notifications
}

Check-agent
$enrollment = Get-Enrollment

Uninstall-Hub
$enrollment = Get-Enrollment

if ($enrollment -eq $false) { #checking to ensure MDM enrollment is false before attempting to enroll hub
    Enroll-Hub
    Get-Enrollment
}

if ($silent) {
    enable-notifications
    Remove-Item -Path "$logpath\vars.txt" -Force -ErrorAction SilentlyContinue 
    Write-Log "Silent: Deleting vars.txt file"	
}

