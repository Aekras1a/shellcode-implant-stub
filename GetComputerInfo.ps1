# GetComputerInfo
# A demonstration script which uses WMI calls to retrieve system information
# The WMI classes can be derived from https://msdn.microsoft.com/en-us/library/windows/desktop/aa389273%28v=vs.85%29.aspx
#
# Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>
# Part of the shellcode-implant-stub project

function GetComputerInfo {

    # Domain, Manufacturer, Model etc
    Get-WmiObject Win32_ComputerSystem 

    # OS Registered user, serial number etc
    Get-WmiObject Win32_OperatingSystem

    # BIOS Information
    Get-WmiObject Win32_BIOS 

    # CPU Specific Information
    Get-WmiObject Win32_Processor 
	
	# Motherboard Information
	Get-WmiObject Win32_BaseBoard 

}