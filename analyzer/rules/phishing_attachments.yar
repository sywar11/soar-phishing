/*
  Règles YARA appliquées aux pièces jointes (et aux fichiers contenus dans les ZIP / OOXML).
  La méta "score" est reprise telle quelle par le moteur de score.
*/

rule HTML_Credential_Harvesting
{
    meta:
        description = "Page HTML avec formulaire demandant un mot de passe (page de phishing jointe)"
        score = 30
    strings:
        $form = "<form" nocase
        $pwd1 = "type=\"password\"" nocase
        $pwd2 = "type='password'" nocase
        $pwd3 = "type=password" nocase
    condition:
        $form and any of ($pwd*)
}

rule HTML_Smuggling
{
    meta:
        description = "HTML smuggling : fichier reconstruit en JavaScript (atob + Blob + téléchargement)"
        score = 35
    strings:
        $a = "atob(" nocase
        $b = "new Blob" nocase
        $c1 = "msSaveOrOpenBlob" nocase
        $c2 = ".download" nocase
        $c3 = "createObjectURL" nocase
    condition:
        $a and $b and any of ($c*)
}

rule HTML_Obfuscated_Redirect
{
    meta:
        description = "Redirection JavaScript obfusquée (window.location + unescape/atob/fromCharCode)"
        score = 20
    strings:
        $loc1 = "window.location" nocase
        $loc2 = "location.href" nocase
        $loc3 = "location.replace" nocase
        $obf1 = "unescape(" nocase
        $obf2 = "atob(" nocase
        $obf3 = "fromCharCode" nocase
    condition:
        any of ($loc*) and any of ($obf*)
}

rule Office_VBA_Macro
{
    meta:
        description = "Document Office contenant des macros VBA"
        score = 25
    strings:
        $ooxml = "vbaProject.bin" nocase
        $ole_vba = "_VBA_PROJECT" wide ascii
        $attr = "Attribute VB_Name" ascii
    condition:
        any of them
}

rule Office_AutoExec_Macro
{
    meta:
        description = "Macro à exécution automatique (AutoOpen / Document_Open / Workbook_Open)"
        score = 35
    strings:
        $a1 = "AutoOpen" nocase ascii wide
        $a2 = "Auto_Open" nocase ascii wide
        $a3 = "Document_Open" nocase ascii wide
        $a4 = "Workbook_Open" nocase ascii wide
        $s1 = "Shell" nocase ascii wide
        $s2 = "WScript" nocase ascii wide
        $s3 = "CreateObject" nocase ascii wide
        $s4 = "URLDownloadToFile" nocase ascii wide
    condition:
        any of ($a*) and any of ($s*)
}

rule Suspicious_PowerShell
{
    meta:
        description = "Lancement PowerShell encodé / téléchargement en mémoire"
        score = 35
    strings:
        $ps = "powershell" nocase ascii wide
        $e1 = "-enc" nocase ascii wide
        $e2 = "FromBase64String" nocase ascii wide
        $e3 = "IEX" ascii wide
        $e4 = "DownloadString" nocase ascii wide
        $e5 = "Invoke-Expression" nocase ascii wide
        $e6 = "-w hidden" nocase ascii wide
    condition:
        $ps and any of ($e*)
}

rule Windows_Executable
{
    meta:
        description = "Exécutable Windows (PE) en pièce jointe"
        score = 40
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Windows_Shortcut_LNK
{
    meta:
        description = "Raccourci Windows (.lnk) - vecteur fréquent de chargement de malware"
        score = 35
    condition:
        uint32(0) == 0x0000004C
}

rule Script_Dropper
{
    meta:
        description = "Script Windows (JS/VBS/HTA) utilisant WScript/ActiveX"
        score = 35
    strings:
        $w1 = "WScript.Shell" nocase
        $w2 = "ActiveXObject" nocase
        $w3 = "Scripting.FileSystemObject" nocase
        $w4 = "<HTA:APPLICATION" nocase
    condition:
        any of them
}

rule PDF_Active_Content
{
    meta:
        description = "PDF avec JavaScript ou action de lancement"
        score = 25
    strings:
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $l = "/Launch"
        $o = "/OpenAction"
    condition:
        uint32(0) == 0x46445025 and ($l or ($o and any of ($js*)))
}

rule Disk_Image_ISO
{
    meta:
        description = "Image disque ISO (contournement Mark-of-the-Web)"
        score = 25
    strings:
        $cd001 = "CD001"
    condition:
        $cd001 at 0x8001 or $cd001 at 0x8801 or $cd001 at 0x9001
}
