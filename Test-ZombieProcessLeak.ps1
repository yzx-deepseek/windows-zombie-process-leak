<#
.SYNOPSIS
  Detects whether exited processes are being leaked as "zombie" process objects
  on this Windows machine, and reports AMD display driver versions.

.DESCRIPTION
  Reads the kernel pool tag counters for the 'Proc' tag (one allocation per
  process object) via NtQuerySystemInformation(SystemPoolTagInformation),
  compares it with the number of live processes, then starts N short-lived
  cmd.exe processes and checks how many process objects were NOT freed.

  On a healthy system, retained objects after the test should be ~0.
  On an affected system, retained objects ~= N (every exited process leaks).

  No external tools, no admin rights required for the counters on most systems.

.PARAMETER Count
  Number of short-lived processes to start (default 200).
#>
param([int]$Count = 200)

Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class PoolTag {
  [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int c, IntPtr b, int l, out int r);
  // SystemPoolTagInformation = 22. x64 SYSTEM_POOLTAG is 40 bytes:
  // Tag(4) PagedAllocs(4) PagedFrees(4) pad(4) PagedUsed(8) NonPagedAllocs(4) NonPagedFrees(4) NonPagedUsed(8)
  public static long[] Get(string tag) {
    int len = 1 << 20; IntPtr buf; int ret;
    while (true) { buf = Marshal.AllocHGlobal(len); int s = NtQuerySystemInformation(22, buf, len, out ret);
      if (s == 0) break; Marshal.FreeHGlobal(buf); if (len > (1 << 26)) throw new Exception("query failed 0x" + s.ToString("X")); len *= 2; }
    try {
      int n = Marshal.ReadInt32(buf); int want = BitConverter.ToInt32(System.Text.Encoding.ASCII.GetBytes(tag), 0);
      for (int i = 0; i < n; i++) { IntPtr e = buf + 8 + i * 40;
        if (Marshal.ReadInt32(e) == want) {
          long na = (uint)Marshal.ReadInt32(e + 24), nf = (uint)Marshal.ReadInt32(e + 28), nu = Marshal.ReadInt64(e + 32);
          return new long[] { na - nf, nu }; } }
      return new long[] { -1, -1 };
    } finally { Marshal.FreeHGlobal(buf); }
  }
  // Returns "tag<TAB>pool<TAB>bytes" for every tag
  public static string[] All() {
    int len = 1 << 20; IntPtr buf; int ret;
    while (true) { buf = Marshal.AllocHGlobal(len); int s = NtQuerySystemInformation(22, buf, len, out ret);
      if (s == 0) break; Marshal.FreeHGlobal(buf); len *= 2; }
    try {
      int n = Marshal.ReadInt32(buf); var list = new System.Collections.Generic.List<string>();
      for (int i = 0; i < n; i++) { IntPtr e = buf + 8 + i * 40;
        byte[] t = new byte[4]; Marshal.Copy(e, t, 0, 4); string tag = System.Text.Encoding.ASCII.GetString(t);
        list.Add(tag + "\tPaged\t" + Marshal.ReadInt64(e + 16)); list.Add(tag + "\tNonpaged\t" + Marshal.ReadInt64(e + 32)); }
      return list.ToArray();
    } finally { Marshal.FreeHGlobal(buf); }
  }
}
"@

function Get-ProcObjects { [PoolTag]::Get('Proc')[0] }

$os = Get-CimInstance Win32_OperatingSystem
$uptime = (Get-Date) - $os.LastBootUpTime
$live = @(Get-Process).Count
$before = Get-ProcObjects

Write-Host ("Windows build      : {0}" -f $os.BuildNumber)
Write-Host ("Uptime             : {0:N1} hours" -f $uptime.TotalHours)
Write-Host ("Live processes     : {0}" -f $live)
Write-Host ("Process objects    : {0}  (kernel 'Proc' pool tag, outstanding)" -f $before)
Write-Host ("Excess objects     : {0}  (should be close to 0 on a healthy system)" -f ($before - $live))

Write-Host ""
Write-Host "Largest kernel pool tags right now:"
$top = [PoolTag]::All() | ForEach-Object { $f = $_ -split "`t"; [pscustomobject]@{ Tag = $f[0].Trim([char]0, ' '); Pool = $f[1]; MB = [math]::Round([int64]$f[2] / 1MB, 1) } } |
  Sort-Object MB -Descending | Select-Object -First 8
$top | ForEach-Object { Write-Host ("  {0,-5} {1,-9} {2,10:N1} MB" -f $_.Tag, $_.Pool, $_.MB) }
# Only tags above 1 GB are treated as a symptom; a few hundred MB is normal.
$tags = $top | Where-Object { $_.MB -gt 1024 } | Select-Object -ExpandProperty Tag
if (-not $tags) { Write-Host "No kernel pool tag is above 1 GB right now (normal)." -ForegroundColor Green }
Write-Host ""
if ($tags -contains 'NtFC') { Write-Host "Hint: 'NtFC' is large -> bindflt/file-probe leak (e.g. Codex/Chromium GPU shader cache). See README section 'Which leak do I have?'." -ForegroundColor Yellow }
if (($tags -contains 'FMfn') -or ($tags -contains 'File') -or ($tags -contains 'IoFE')) { Write-Host "Hint: 'FMfn'/'File'/'IoFE' are large -> file-system filter driver path (antivirus/Defender minifilters). See README." -ForegroundColor Yellow }
if (($tags -contains 'Proc') -or ($tags -contains 'Toke') -or ($tags -contains 'MiP2')) { Write-Host "Hint: 'Proc'/'Toke'/'MiP2' are large -> zombie process objects (this test). Check your GPU driver." -ForegroundColor Yellow }
Write-Host ""

Get-CimInstance Win32_VideoController | ForEach-Object {
  Write-Host ("GPU                : {0} | driver {1} | {2:yyyy-MM-dd}" -f $_.Name, $_.DriverVersion, $_.DriverDate)
}

Write-Host ""
Write-Host "Starting $Count short-lived processes (cmd /c exit)..."
cmd.exe /c "for /l %i in (1,1,$Count) do @cmd /c exit"
Start-Sleep -Seconds 10
$after = Get-ProcObjects
$liveAfter = @(Get-Process).Count
# Subtract processes that are simply still alive (started by other software during the test)
$retained = ($after - $before) - ($liveAfter - $live)

Write-Host ("Process objects retained after test: {0} of {1}" -f $retained, $Count)
if ($retained -ge 0.8 * $Count) {
  Write-Host "RESULT: AFFECTED - exited processes are not being freed (kernel reference leak)." -ForegroundColor Red
  Write-Host "Each leaked process keeps roughly 100 KB of committed memory until reboot."
  Write-Host "If you have an AMD Radeon integrated/discrete GPU on an old driver, update it and re-run this test."
} elseif ($retained -ge 0.1 * $Count) {
  Write-Host "RESULT: INCONCLUSIVE - other software may have started/exited processes during the test. Close busy apps and re-run." -ForegroundColor Yellow
} else {
  Write-Host "RESULT: OK - process objects are being freed normally." -ForegroundColor Green
}
