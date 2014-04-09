//WlanScan - Trigger scans for wireless networks, show visible networks, and list established connection profiles

#include <Windows.h>
#include <VersionHelpers.h>					//Restricting to Vista+ to use API version 2
#include <Wlanapi.h>						//Wlan functions 
#include <wtypes.h>							//Wlan types
#include "pugixml.hpp"						//Open source XML library for parsing wireless network profiles
#include <iostream>							//wcout and endl
#include <iomanip>							//setw and left
#include <io.h>								//This and fcntl.h are needed for _setmode call to allow outputting in unicode
#include <fcntl.h>							

#pragma comment(lib, "wlanapi.lib")			//Link against wlanapi.lib for the wlan APIs

using std::wcout;
using std::endl;
using std::left;
using std::setw;

wchar_t version[] = { L"0.0.1" };			//Version, printed in help output

void showhelp();							//Prints the help text
void shownetworks();						//Shows information on visible networks
void showprofiles();						//Shows information on saved wireless network profiles
void triggerscan();							//Triggers a scan on each wireless network interface
bool checkAdmin();							//Function to check if we're an Admin. Decrypted key information requires this

void wlanInit(HANDLE &wlanHandle, PWLAN_INTERFACE_INFO_LIST &interfaces);			//Function to open the Wlan API handle and gets interface info
void wlanCallback(WLAN_NOTIFICATION_DATA *scanNotificationData, PVOID myContext);	//Function to receive callback notifications for the wireless network scanning

//Context to pass along with callbacks
typedef struct _WLAN_CALLBACK_INFO {
	GUID interfaceGUID;
	HANDLE scanEvent;
	DWORD callbackReason;
} WLAN_CALLBACK_INFO;


int wmain(int argc, wchar_t * argv[])
{

	//Set stdout translation to unicode text. This allows us to output unicode characters like \u2713
	_setmode(_fileno(stdout), _O_U16TEXT);
	wcout << endl;
	
	
	//Windows XP is not supported due to differences in the Wlan API. 
	if (!IsWindowsVistaOrGreater())
	{
		wcout << "Operating system must be Windows Vista or newer." << endl;
		return 0;
	}


	//The C++ standard requires that if there are any parameters, the first parameter will be
	//the name used to invoke the program. So argc needs to be greater than one for us to have
	//any parameters. If there aren't any, we should print the help text and exit.
	if (argc < 2)
	{
		showhelp();
		return 0;
	}
	

	//We'll use wcscmp to match parameters passed in against what we support. It returns 0 for exact string matches.
	if (wcscmp(L"/?", argv[1]) == 0)
	{
		showhelp();
	}
	else if (wcscmp(L"/shownetworks", argv[1]) == 0)
	{
		shownetworks();
	}
	else if (wcscmp(L"/showprofiles", argv[1]) == 0)
	{
		showprofiles();
	}
	else if (wcscmp(L"/triggerscan", argv[1]) == 0)
	{
		triggerscan();
	}
	else
	{
		//A command line parameter was passed, but it wasn't one we support.
		wcout << "Unrecognized command line. Run /? for help." << endl;
	}		

	return 0;
}

void showhelp()
{
	wcout << "WlanScan - A small utility for triggering scans for wireless networks.\n"
		<< "\n"
		<< "   /triggerscan			Triggers a scan for wireless networks.\n"
		<< "   /shownetworks		Shows visible wireless networks.\n"
		<< "   /showprofiles		Shows saved wireless network profiles.\n"
		<< "\n"
		<< "\n"
		<< "\n"
		<< "Version: " << version
		<< "\n";

	return;
}

void wlanInit(HANDLE &wlanHandle, PWLAN_INTERFACE_INFO_LIST &interfaces)
{
	HRESULT result = 0;								//HRESULT to store the return value from Wlan API calls
	DWORD negotiatedVersion = 0;					//DWORD for the Wlan API to store the negotiated API version in

	//Open a handle to the Wlan API
	result = WlanOpenHandle(
		WLAN_API_VERSION_2_0,						//Request API version 2.0
		NULL,										//Reserved
		&negotiatedVersion,							//Address of the DWORD to store the negotiated version
		&wlanHandle									//Address of the HANDLE to store the Wlan handle
		);

	//If the result isn't NO_ERROR, something went wrong. Print the error message and error code, then exit.
	if (result != NO_ERROR)
	{
		wcout << "Error encountered. Code: " << result << endl;
		ExitProcess(result);
	}


	//Enumerate the wireless network interfaces
	result = WlanEnumInterfaces(
		wlanHandle,									//The HANDLE returned by WlanOpenHandle
		NULL,										//Reserved
		&interfaces									//Address of the pointer to store the location to the interface data in
		);

	//If the result isn't NO_ERROR, something went wrong. Print the error message and error code, then exit.
	if (result != NO_ERROR)
	{
		wcout << "Error encountered. Code: " << result << endl;
		ExitProcess(result);
	}


	//Let's output that there are 0, 1 or # interfaces on the system
	//dwNumberOfItems is included in the WLAN_INTERFACE_INFO_LIST we got from WlanEnumInterfaces
	if (interfaces->dwNumberOfItems == 0)
	{
		wcout << "There are no wireless interfaces available." << endl;
	}
	else if (interfaces->dwNumberOfItems == 1)
	{
		wcout << "There is 1 wireless interface available." << endl << endl;
	}
	else
	{
		wcout << "There are " << interfaces->dwNumberOfItems << " wireless interfaces available." << endl << endl;
	}

	return;

}

void shownetworks()
{
	HRESULT result = 0;								//HRESULT to store the result of Wlan API calls
	HANDLE wlanHandle = NULL;						//HANDLE to the Wlan API
	PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;	//PWLAN_INTERFACE_INFO_LIST pointer for the interface data returned by the Wlan API

	//Get the Wlan API handle and interface info
	wlanInit(wlanHandle, interfaces);

	//For each interface on the system, we'll print the name and number.
	for (ULONG i = 0; i < interfaces->dwNumberOfItems; i++)
	{
		wcout << "\tInterface " << i + 1 << ": " << interfaces->InterfaceInfo[i].strInterfaceDescription << endl;

		PWLAN_AVAILABLE_NETWORK_LIST networks = nullptr;				//PWLAN_AVAILABLE_NETWORK_LIST pointer for the data returned by the Wlan API
		
		//Get the list of visible wireless networks
		result = WlanGetAvailableNetworkList(					
			wlanHandle,													//The HANDLE returned by WlanOpenHandle
			&(interfaces->InterfaceInfo[i].InterfaceGuid),				//The wireless network interface to get network data from
			WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES |			//Include all ad hoc network profiles in the available network list, including profiles that are not visible
			WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,	//And include all hidden network profiles in the available network list, including profiles that are not visible
			NULL,														//Reserved
			&networks													//Address of the pointer to store the location to the network data in
			);
		
		//If the result isn't NO_ERROR, something went wrong. Print the error message and error code, then continue to the next interface in the for loop.
		if (result != NO_ERROR)
		{
			wcout << "\tError encountered. Code: " << result << endl;
			continue;
		}

		
		//Print a clean header, tabbed in and spaced out
		wcout << endl;
		wcout << "\t" << setw(40) << left << "Visible Networks" << setw(12) << left << "Secured" << "Signal %" << endl;
		wcout << "\t" << setw(40) << left << "----------------" << setw(12) << left << "-------" << "--------" << endl;

		//Loop over the visible networks returned by the Wlan API
		for (ULONG num = 0; num < networks->dwNumberOfItems; num++)
		{

			// The network name is an unsigned char, but we need a wchar_t to print it
			//So for each character in the SSID, let's convert the unsigned char a wchar_t and store it in networkSSID[]
			wchar_t networkSSID[255] = { L'\0' };						
			for (ULONG a = 0; a < networks->Network[num].dot11Ssid.uSSIDLength; a++)
			{
				networkSSID[a] = btowc(networks->Network[num].dot11Ssid.ucSSID[a]);
			}
				
			//								     Network Name					      If security is enabled, print a checkmark, else leave a blank						          Signal quality
			wcout << "\t" << setw(40) << left << networkSSID << setw(12) << left << (networks->Network[num].bSecurityEnabled ? L"   \u2713" : L"    ") << "   " << networks->Network[num].wlanSignalQuality << endl;

		}

		//Print the total number of visible networks.
		wcout << endl;
		wcout << "\t  Total number of networks: " << networks->dwNumberOfItems << endl << endl;

		//And free the memory the Wlan API allocated for us
		WlanFreeMemory(networks);

		wcout << endl;

	}


	//Let's free the memory the Wlan API allocated for us and close the handle we opened
	WlanFreeMemory(interfaces);						//Pointer to the PWLAN_WLAN_INTERFACE_INFO_LIST data
	WlanCloseHandle(wlanHandle, NULL);				//The Wlan HANDLE and a Reserved value

	return;
}

bool checkAdmin()
{
	BOOL isAdmin = FALSE;											//Bool to store the result of our check in
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;	//The authority the Administrators group sits under
	PSID AdministratorsGroup = nullptr;								//Pointer to the SID we'll be testing against

	
	AllocateAndInitializeSid(										//Get an SID representing the Administrators group to test against
		&NtAuthority,												//The authority is NtAuthority
		2,															//We have two groups to include
		SECURITY_BUILTIN_DOMAIN_RID,								//Domain admins
		DOMAIN_ALIAS_RID_ADMINS,									//And their alias
		0, 0, 0, 0, 0, 0,											//We don't need the other slots
		&AdministratorsGroup);										//Where the SID should be stored
	
	if (AdministratorsGroup == nullptr)
	{
		//Something went wrong getting our SID. Assume we're not an Administrator
		return false;
	}

	//Check whether our token is part of the Administrators group. If the function fails, assume we're not an Administrator
	if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin))
	{
		FreeSid(AdministratorsGroup);
		return false;
	}

	//We have the answer now in isAdmin, so free the SID we got
	FreeSid(AdministratorsGroup);

	if (isAdmin)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void showprofiles()
{
	using namespace pugi;							//Using functions from the pugi namespace to parse XML profile info
	HRESULT result = 0;								//HRESULT to store the result of Wlan API calls
	HANDLE wlanHandle = NULL;						//HANDLE to the Wlan API
	PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;	//PWLAN_INTERFACE_INFO_LIST pointer for the interface data returned by the Wlan API

	//Get the Wlan API handle and interface info
	wlanInit(wlanHandle, interfaces);

	//For each interface on the system, we'll print the name and number.
	for (ULONG i = 0; i < interfaces->dwNumberOfItems; i++)
	{
		wcout << "\tInterface " << i + 1 << ": " << interfaces->InterfaceInfo[i].strInterfaceDescription << endl;

		//Get the list of profiles for the interface
		PWLAN_PROFILE_INFO_LIST pProfileInfoList = nullptr;
		result = WlanGetProfileList(wlanHandle, &(interfaces->InterfaceInfo[i].InterfaceGuid), NULL, &pProfileInfoList);
		if (result != ERROR_SUCCESS)
		{
			wcout << "\tError retreiving profile list. Error: " << result << endl;
			continue;
		}

		//Ensure there is at least one profile
		if (pProfileInfoList->dwNumberOfItems < 1)
		{
			wcout << "\tThere are no profiles for this interface." << endl;
			continue;
		}


		//Print a header
		wcout << endl;
		wcout << "\t" << setw(21) << left << "Profile Name" << setw(16) << left << "Profile Type" << setw(12) << left << "Security" << "Auth Secret" << endl;
		wcout << "\t" << setw(21) << left << "------------" << setw(16) << left << "------------" << setw(12) << left << "--------" << "-----------" << endl;


		//And loop over the profile list
		for (ULONG j = 0; j < pProfileInfoList->dwNumberOfItems; j++)
		{

			LPWSTR xmlProfileInfo = nullptr;							//Pointer to the XML profile returned by the Wlan API
			xml_document xmlProfileDoc;									//Pugi xml_document to load that XML profile in
			DWORD dwFlags = NULL;										//Flags value to send/receive info with the API
			bool decryptKey = false;									//Bool for whether or not we can get the decrypted keys

			//If we're on Windows 7 and we're an Administrator we can ask for the plaintext key
			if (IsWindows7OrGreater() && checkAdmin())
			{
				dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
				decryptKey = true;
			}

			result = WlanGetProfile(									//Get the specific profile info
				wlanHandle,												//Wlan API handle
				&(interfaces->InterfaceInfo[i].InterfaceGuid),			//Interface GUID
				pProfileInfoList->ProfileInfo[j].strProfileName,		//Profile name
				NULL,													//Reserved
				&xmlProfileInfo,										//Pointer to store the profile in
				&dwFlags,												//Flags to potentially request decrypted key and to recieve profile type
				NULL													//Access mask for the profile, not of interest to me
				);


			if (result != ERROR_SUCCESS)
			{
				//We were not able to get info on this profile. Print the name and continue to the next one
				wcout << "\t" << pProfileInfoList->ProfileInfo[j].strProfileName << endl;
				continue;
			}

			//Print the profile name
			wcout << "\t" << setw(21) << left << pProfileInfoList->ProfileInfo[j].strProfileName << setw(16) << left;

			//The dwFlags value will have the profile type. Check and print the type as appropriate
			if (dwFlags == WLAN_PROFILE_GROUP_POLICY)
			{
				wcout << "Group Policy";
			}
			else if (dwFlags == WLAN_PROFILE_USER)
			{
				wcout << "User Profile";
			}
			else
			{
				wcout << "All Users";
			}


			//And load the XML returned by the Wlan API in pugi
			xmlProfileDoc.load(xmlProfileInfo);

			//Open up the security and authentication nodes
			xml_node securityNode = xmlProfileDoc.child(L"WLANProfile").child(L"MSM").child(L"security");
			xml_node authentication = securityNode.child(L"authEncryption").child(L"authentication");


			//If the authentication node doesn't exist, something is very off with the profile. Print unrecognized and continue
			if (!authentication)
			{
				wcout << setw(12) << left << L"Unrecognized" << L"" << endl;
				continue;
			}

			//Create an xml_text variable to grab the authentication text as a string to compare against
			xml_text authenticationType = authentication.text();


			//Check if the security type is open. If so, print Open and continue
			if ((wcscmp(authenticationType.as_string(), L"open")) == 0)
			{
				wcout << setw(12) << left << L"Open" << L"" << endl;
				continue;
			}

			//Shared, WPAPSK, and WPAPSK2 are all very similar authentication styles
			else if ((wcscmp(authenticationType.as_string(), L"shared") == 0) || (wcscmp(authenticationType.as_string(), L"WPAPSK") == 0) || (wcscmp(authenticationType.as_string(), L"WPA2PSK") == 0))
			{

				//If the type is shared, print the name as WEP instead. (Most don't know 'shared' vs WEP)
				if ((wcscmp(authenticationType.as_string(), L"shared") == 0))
				{
					wcout << setw(12) << left << L"WEP" << L"" << endl;
				}
				else
				{
					//Otherwise the names WPAPSK and WPAPSK2 are fine to print as is
					wcout << setw(12) << left << authenticationType.as_string();
				}


				//All three encryption types have a sharedKey keyMaterial block
				xml_text keyMaterial = securityNode.child(L"sharedKey").child(L"keyMaterial").text();

				//If we could decrypt the key, then print the plaintext
				if (decryptKey)
				{
					wcout << keyMaterial.as_string() << endl;
					continue;
				}
				else
				{
					//Otherwise it will be encrypted gibberish so print Encrypted instead
					wcout << L"<Encrypted>" << endl;
					continue;
				}
			}
			//Finally, if the authentication is WPA or WPA2, we're dealing with the enterprise variants
			else if ((wcscmp(authenticationType.as_string(), L"WPA") == 0) || (wcscmp(authenticationType.as_string(), L"WPA2") == 0))
			{
				//Printing the name as is is fine
				wcout << setw(12) << left << authenticationType.as_string();

				//And we can get the specific type of WPA / WPA2 by nestling down for the Type value
				xml_text EAPType = securityNode.child(L"OneX").child(L"EAPConfig").child(L"EapHostConfig").child(L"EapMethod").child(L"Type").text();
				
				//Print the type
				if (EAPType.as_int())
				{
					wcout << L"<EAP Type " << EAPType.as_int() << ">" << endl;
				}
				else
				{
					wcout << L"<EAP Type Unknown>" << endl;
				}
					
				continue;
			}
			//It shouldn't be possible to end up here, but maybe in the future with new authentication styles?
			else
			{
				//Set the security type to whatever it is in the profile
				wcout << setw(12) << left << authenticationType.as_string() << L"" << endl;
				
				//And continue since we don't know how to parse this profile
				continue;
			}
		}

		wcout << endl << endl;
	}

	return;
}

void triggerscan()
{
	HRESULT result = 0;								//HRESULT to store the result of Wlan API calls
	HANDLE wlanHandle = NULL;						//HANDLE to the WLAN api
	PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;	//PWLAN_INTERFACE_INFO_LIST pointer for the interface data returned by the Wlan API

	wlanInit(wlanHandle, interfaces);				//Get the Wlan API handle and interface info

	//For each interface on the system, we'll print the name and number.
	for (ULONG i = 0; i < interfaces->dwNumberOfItems; i++)
	{
		wcout << "\tInterface " << i + 1 << ": " << interfaces->InterfaceInfo[i].strInterfaceDescription << endl << endl;

		//Declare the callback parameter struct
		WLAN_CALLBACK_INFO callbackInfo = { 0 };
		callbackInfo.interfaceGUID = interfaces->InterfaceInfo[i].InterfaceGuid;

		//Create an event to be triggered in the scan case
		callbackInfo.scanEvent = CreateEvent(
			nullptr,
			FALSE, 
			FALSE, 
			nullptr);


		//Register for wlan scan notifications
		WlanRegisterNotification(wlanHandle, 
			WLAN_NOTIFICATION_SOURCE_ALL, 
			TRUE, 
			(WLAN_NOTIFICATION_CALLBACK)wlanCallback, 
			(PVOID)&callbackInfo, 
			NULL, 
			NULL);
				

		//Start a scan. If the WlanScan call fails, log the error
		WlanScan(wlanHandle, &(interfaces->InterfaceInfo[i].InterfaceGuid), NULL, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS)
		{
			wcout << "\tError triggering scan on interface " << i + 1 << ". Error: " << GetLastError() << endl;
			continue;
		}
		else
		{
			//Scan request successfully sent
			wcout << "\tScan request sent. Waiting for reply." << endl;
		}

				
		//Wait for the event to be signaled, or an error to occur. Don't wait longer than 15 seconds.
		DWORD waitResult = WaitForSingleObject(callbackInfo.scanEvent, 15000);

		//Check how we got here, via callback or timeout
		if (waitResult == WAIT_OBJECT_0) 
		{
			if (callbackInfo.callbackReason == wlan_notification_acm_scan_complete) 
			{
				wcout << "\tReply: The scan for networks has completed." << endl << endl;
			}
			else if (callbackInfo.callbackReason == wlan_notification_acm_scan_fail)
			{
				wcout << "\tReply: The scan for connectable networks failed." << endl << endl;
			}

			
		}
		else if (waitResult == WAIT_TIMEOUT)
		{
			wcout << "\tError: No response was received after 15 seconds." << endl;
			wcout << "\n\tWindows Logo certified wireless drivers are required to complete scans\n"
				  << "\tin under four seconds, so there may be something wrong." << endl << endl;
		}
		else 
		{
			wcout << "\n\tUnknown error waiting for response. Error Code: " << waitResult << endl << endl;
		}

		wcout << endl;
	}
	
	//Let's free the memory the Wlan API allocated for us and close the handle we opened
	WlanFreeMemory(interfaces);						//Pointer to the PWLAN_WLAN_INTERFACE_INFO_LIST data
	WlanCloseHandle(wlanHandle, NULL);				//The Wlan HANDLE and a Reserved value
	return;
}

void wlanCallback(WLAN_NOTIFICATION_DATA *scanNotificationData, PVOID myContext)
{
	//Get the data from my struct. If it's null, nothing to do
	WLAN_CALLBACK_INFO* callbackInfo = (WLAN_CALLBACK_INFO*)myContext;
	if (callbackInfo == nullptr) 
	{
		return;
	}

	//Check the GUID in the struct against the GUID in the notification data, return if they don't match
	if (memcmp(&callbackInfo->interfaceGUID, &scanNotificationData->InterfaceGuid, sizeof(GUID)) != 0) 
	{
		return;
	}

	//If the notification was for a scan complete or failure then we need to set the event
	if ((scanNotificationData->NotificationCode == wlan_notification_acm_scan_complete) || (scanNotificationData->NotificationCode == wlan_notification_acm_scan_fail))
	{
		//Set the notification code as the callbackReason
		callbackInfo->callbackReason = scanNotificationData->NotificationCode;

		//Set the event
		SetEvent(callbackInfo->scanEvent);
	}
	
	return;	
}