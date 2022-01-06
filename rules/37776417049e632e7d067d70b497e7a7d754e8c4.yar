rule crime_trickbot_network_module_in_memory {   
    meta:   
     description = "Detects Trickbot network module in memory"   
     author = "@VK_Intel"   
     reference = "Detects unpacked Trickbot network64Dll"   
     date = "2018-04-02"   
     hash = "0df586aa0334dcbe047d24ce859d00e537fdb5e0ca41886dab27479b6fc61ba6"   
    strings:   
     $s0 = "***PROCESS LIST***" fullword wide   
     $s1 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" fullword wide   
     $s2 = "***USERS IN DOMAIN***" fullword wide   
     $s3 = "Operating System: %ls" fullword wide   
     $s4 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetCon" ascii   
     $s5 = "Content-Length: %lu" fullword wide   
     $s6 = "Boot Device - %ls" fullword wide   
     $s7 = "Serial Number - %ls" fullword wide   
     $s8 = "Content-Disposition: form-data; name=\"proclist\"" fullword ascii   
     $s9 = "Content-Disposition: form-data; name=\"sysinfo\"" fullword ascii   
     $s10 = "Product Type - Server" fullword wide   
     $s11 = "***SYSTEMINFO***" fullword wide   
     $s12 = "OS Version - %ls" fullword wide   
     $s13 = "(&(objectcategory=person)(samaccountname=*))" fullword wide   
     $s14 = "Product Type - Domain Controller" fullword wide   
    condition:   
     uint16(0) == 0x5a4d and filesize < 70KB and 12 of ($s*)   
   }