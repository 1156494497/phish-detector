$conn = Get-NetTCPConnection -LocalPort 8899 -ErrorAction SilentlyContinue
if ($conn) {
    foreach ($c in $conn) {
        $pid = $c.OwningProcess
        try {
            $p = Get-Process -Id $pid -ErrorAction Stop
            Write-Output "PID=$pid Name=$($p.ProcessName) Path=$($p.Path)"
        } catch {
            Write-Output "PID=$pid Name=(not found) Path=(not found)"
        }
    }
} else {
    Write-Output "port_free"
}
