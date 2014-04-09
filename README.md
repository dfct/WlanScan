wlanscan
========

Trigger scans for wireless networks, show visible networks, and list established connection profiles.

Output from /?:
```
WlanScan - A small utility for triggering scans for wireless networks.

   /triggerscan                 Triggers a scan for wireless networks.
   /shownetworks                Shows visible wireless networks.
   /showprofiles                Shows saved wireless network profiles.



Version: 0.0.1
```

The x86 binary was compiled with Visual Studio 2013, so you'll need the [Visual C++ 2013 redistributables](http://www.microsoft.com/en-us/download/details.aspx?id=40784) installed to run it as is. Of course, you can also compile wlanscan.cpp with the compiler of your choice as well.


I wrote this when I couldn't find an existing tool to scan for wireless networks. The built-in Windows netsh.exe won't actually trigger a new scan, it can only show previously-found networks which may be stale. 

Features like parsing profiles ended up in there as this also became a fun introduction to Wlan apis :)
