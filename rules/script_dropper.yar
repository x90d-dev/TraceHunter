/*
   TraceHunter YARA Rule Set: Script Dropper & Living-off-the-Land Stagers
   Repository: https://github.com/x90d-dev/TraceHunter
   MITRE ATT&CK: T1059.001 / T1105 (Ingress Tool Transfer)
*/

rule TraceHunter_ScriptDropper_Stager {
    meta:
        author = "x90d"
        description = "Detects PowerShell, WScript, and LOLBin download-and-execute dropper patterns"
        mitre_id = "T1059.001"
        severity = "HIGH"
    strings:
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString(" nocase
        $dl3 = "DownloadFile(" nocase
        $dl4 = "Invoke-WebRequest" nocase
        $dl5 = "FromBase64String(" nocase
        $ex1 = "Invoke-Expression" nocase
        $ex2 = "IEX(" nocase
        $ex3 = "-WindowStyle Hidden" nocase
        $ex4 = "-EncodedCommand" nocase
        $lol1 = "certutil.exe -urlcache -split -f" nocase
        $lol2 = "bitsadmin /transfer" nocase
    condition:
        ((1 of ($dl*)) and (1 of ($ex*))) or (1 of ($lol*))
}
