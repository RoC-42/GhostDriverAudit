# GhostDriverAudit (GDA)
A PowerShell script that checks Windows 11 installations for orphaned drivers

==========
DISCLAIMER: Use at your own risk!
This script operates deep inside Windows 11 OS, and may lead to a situation where i.e. the PC does not respond anymore.
In this case the Windows recovery environment (WinPE) must be loaded and a restore point must be restored.
==========

Use Case
==========
In many cases, Windows installations have developed through extended cycles of upgrades (Win 8 > Win 10 > Win 11) and often also acrsoss different hardware (i.e. PC Build 1 > PC Build 2). 
Additionally, many software and drivers may have been installed and deinstalled over time.
Both scenarios lead to lots of orphaned drivers, some of them rooted deep in the system. 
In some cases these lead to errors and even fatal crashes if removed manually, i.e. motherboard software suites (i.E. ASUS AI Suite, MSI Dragon Center etc.). 
More often, Win 11 features such as Core Isolation do not work because of those orphaned drivers.
In some rare cases, even tools like the highly recommended Driver Store Explorer do NOT list those driver dependencies, as they do not reside (anymore) in the driver store of Windows 11. 
Ghost Driver Audit (GDA) addresses these issues.

What Ghost Driver Audit does
==========
The script will create a restore point (as a backup), then check both, UpperFilters and LowerFilters for orphaned drivers, plus the ENUM section of Win11. 
The output will be a list from which all original Microsoft / Windows 11 drivers will be excluded (=not shown). 
All other entries do have entries in the registry, but no physical driver files to load, or they have physical files and a registry entry, but are not in use.
The user can then go through the list 1 by 1 and will be asked whether or not to delete the respective driver entry.
Afterwards, the PC must be rebooted.
