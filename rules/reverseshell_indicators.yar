/*
   TraceHunter YARA Rule Set: Reverse Shell Indicators
   Repository: https://github.com/x90d-dev/TraceHunter
   MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
*/

rule TraceHunter_ReverseShell_Socket_Payloads {
    meta:
        author = "x90d"
        description = "Detects interactive reverse shell one-liners across PowerShell, Bash, and Python"
        mitre_id = "T1059"
        severity = "HIGH"
    strings:
        $ps_tcp = "System.Net.Sockets.TCPClient" nocase
        $ps_stream = "GetStream()" nocase
        $bash_dev = "/dev/tcp/" ascii
        $bash_redir = "0>&1" ascii
        $py_pty = "pty.spawn(\"/bin/sh\")" ascii
        $py_pty_bash = "pty.spawn(\"/bin/bash\")" ascii
        $nc_exec = "nc -e /bin/sh" ascii
        $nc_cmd = "nc.exe -e cmd.exe" nocase
    condition:
        ($ps_tcp and $ps_stream) or ($bash_dev and $bash_redir) or $py_pty or $py_pty_bash or $nc_exec or $nc_cmd
}
