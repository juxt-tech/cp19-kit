# Practice-VM test harness

> **PRACTICE VMs ONLY.** The agent is a remote shell that runs as SYSTEM/root. Never install it on a
> competition image, and remove it from any VM you hand to someone else.

Lets the kit be tested on a practice image **with no clicking or typing in the VM** after a one-line
install. Built after District 13 showed what breaks: faked keystrokes landed in the wrong window,
the lock screen stopped an agent that ran in the user's session, and a hung module blocked everything.

| Problem seen | How the harness avoids it |
|---|---|
| Lock screen / sign-out / reboot killed the agent | Windows: scheduled task as **SYSTEM** (at startup + 5-minute watchdog). Linux: **systemd** unit as root, `Restart=always`. Neither needs a signed-in user. |
| VM went to sleep | Standby/hibernate timeouts set to 0 (Windows `powercfg`, Linux sleep targets masked). Screen-saver and inactivity-lock policies are **not** touched: they are scored. |
| A module hung and blocked the agent forever | Every job runs in its own process with a timeout (default 1 h); the host can kill it; the whole process tree goes. |
| No idea whether the VM was alive | Heartbeat every 15 s with uptime, signed-in users and the last lines of the running job. |
| Agent or VM restarted mid-job | Job reported as `interrupted` and **never re-run** (a job that reboots cannot loop). |
| Copy/paste into the VM does not work without VMware Tools | Install command is ~40 characters. |

## Use

Host (once per session) - the server binds to the VMware NAT adapter only:

```powershell
python -I tools\vmtest\server.py 192.168.209.1 8765          # Get-NetIPAddress -InterfaceAlias '*VMnet8' shows the IP
.\tools\vmtest\vmt.ps1 stage-kit                              # kit.zip + kit.tgz from HEAD
.\tools\vmtest\vmt.ps1 stage -Path my-image-config.txt        # jobs fetch it as $CpServer/f/my-image-config.txt
```

Guest (once per VM, then **snapshot** - the agent starts at boot, before anyone signs in):

```
Windows, admin PowerShell:   iex(irm -useb 192.168.209.1:8765/a)
Linux, terminal:             curl -s 192.168.209.1:8765/l | sudo bash      (or: wget -qO- 192.168.209.1:8765/l | sudo bash)
```

Drive it from the host:

```powershell
.\tools\vmtest\vmt.ps1 status
.\tools\vmtest\vmt.ps1 run -Vm win-kkiknthsh95 -Timeout 1800 -Code 'iex (irm -useb "$CpServer/g/cpk.ps1"); Install-Kit my-image-config.txt; Run-Kit audit @("-All")'
.\tools\vmtest\vmt.ps1 run -Vm win-kkiknthsh95 -Code 'iex (irm -useb "$CpServer/g/cpk.ps1"); Run-Kit apply-Services @("-Apply","-Yes","-Module","Services"); Get-Score after-services -Wait 180'
.\tools\vmtest\vmt.ps1 run -Vm ubuntu -Code 'source <(curl -s "$CP_SERVER/g/cpk.sh"); install_kit my-image-config.txt; run_kit audit --all'
.\tools\vmtest\vmt.ps1 kill -Vm ubuntu -N 4
```

Always pass `-All` / `-Module` (Windows) or `--all` / `--module` (Linux): there is nobody to answer the menu.
Results land in `%USERPROFILE%\cpvmtest\vms\<vm>\r\` (`out-<n>.txt`, uploads from `up`, `hb.json`).

## Notes

- `Run-Kit` / `run_kit` run the kit **as the signed-in user** (`USERNAME` / `SUDO_USER`), so the kit
  protects that account exactly as in a real run.
- The kit's Persistence module reports the agent (task `cpkit-test-agent` / unit `cpkit-test-agent`).
  That is expected; it is the kind of thing the kit should flag.
- Jobs: PowerShell on Windows, bash on Linux. Helpers in every job: `up NAME TEXT` (Windows) /
  `up NAME < file` (Linux) uploads a file; `$CpServer`/`$CpVm` and `$CP_SERVER`/`$CP_VM`.
- `vmrun start` must run detached (`Start-Process`). Run from a shell it can hang, and killing that shell powers the VM off. After `revertToSnapshot`, wait for vmware.exe to exit before starting.
- District 13 only: `CSSClient_Restarter.bat` restarts the scorer every 60 s and a pass takes ~135 s on a slow VM, so reports rarely finish. For testing, kill that cmd.exe (not CSSClient): `Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" | ? CommandLine -match CSSClient_Restarter | % { taskkill /PID $_.ProcessId /F }`.
- A snapshot revert or blue screen rolls back the agent's record of finished jobs; the server skips any job with a stored result, so nothing is replayed.
- Remove: `Unregister-ScheduledTask cpkit-test-agent -Confirm:$false; Remove-Item C:\ProgramData\cpagent -Recurse -Force`
  / `sudo systemctl disable --now cpkit-test-agent; sudo rm -rf /var/lib/cpagent /usr/local/sbin/cpkit-test-agent /etc/systemd/system/cpkit-test-agent.service`.
- Tested: Windows agent on a Windows 10 host (jobs, errors, uploads, timeout kills the process tree,
  host kill, crash -> `interrupted`); Linux agent on Ubuntu (curl and wget-only, same cases, plus an
  orphaned job no longer blocking the restarted agent). The SYSTEM task / systemd install itself is
  exercised on the first practice VM.
