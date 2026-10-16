//go:build windows

package schedule

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ruby570bocadito/bastion/internal/probes"
)

// New devuelve el planificador del sistema.
func New() (Scheduler, error) { return taskScheduler{}, nil }

// taskScheduler usa el Programador de tareas de Windows. La ruta del
// ejecutable y la hora llegan a PowerShell por variables de entorno, nunca
// dentro del script.
type taskScheduler struct{}

const (
	taskPath = `\Bastion\`
	taskName = "Escaneo diario"
)

const psTask = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $tp='\Bastion\'; $tn='Escaneo diario'; `

func runPS(ctx context.Context, script string, env ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	exe := probes.System32(`WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+psTask+script)
	cmd.Env = append(os.Environ(), env...)
	b, err := cmd.CombinedOutput()
	out := string(b)
	if !utf8.Valid(b) {
		out = probes.DecodeText(b)
	}
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", filepath.Base(exe), err, strings.TrimSpace(out))
	}
	return out, nil
}

func (taskScheduler) Enable(ctx context.Context, exe, at string) (Status, error) {
	_, err := runPS(ctx, `$a = New-ScheduledTaskAction -Execute $env:BASTION_EXE -Argument 'schedule run'; `+
		`$t = New-ScheduledTaskTrigger -Daily -At $env:BASTION_AT; `+
		`$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1); `+
		// SYSTEM por su SID y, si este Windows no lo admite ahí, por su
		// nombre (que no se traduce).
		`$reg = { param($u) Register-ScheduledTask -TaskPath $tp -TaskName $tn -Action $a -Trigger $t -Settings $s `+
		`-Principal (New-ScheduledTaskPrincipal -UserId $u -LogonType ServiceAccount -RunLevel Highest) `+
		`-Description 'Bastion: escaneo y superficie de ataque diarios (bastion schedule).' -Force | Out-Null }; `+
		`try { & $reg 'S-1-5-18' } catch { & $reg 'SYSTEM' }`,
		"BASTION_EXE="+exe, "BASTION_AT="+at)
	if err != nil {
		return Status{}, err
	}
	return taskScheduler{}.Get(ctx)
}

func (taskScheduler) Disable(ctx context.Context) error {
	_, err := runPS(ctx, `$t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue; `+
		`if ($t) { Unregister-ScheduledTask -TaskPath $tp -TaskName $tn -Confirm:$false }`)
	return err
}

func (taskScheduler) Get(ctx context.Context) (Status, error) {
	out, err := runPS(ctx, `$t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue; `+
		`if (-not $t) { '{}'; return }; $i = $t | Get-ScheduledTaskInfo; `+
		`$at = ''; if ($t.Triggers.Count -gt 0 -and $t.Triggers[0].StartBoundary) { $at = ([datetime]$t.Triggers[0].StartBoundary).ToString('HH:mm') }; `+
		`@{state=[string]$t.State; at=$at; exe=[string]$t.Actions[0].Execute; args=[string]$t.Actions[0].Arguments; `+
		`next=$(if ($i.NextRunTime) { $i.NextRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' }); `+
		`last=$(if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' }); `+
		`result=[int]$i.LastTaskResult} | ConvertTo-Json -Compress`)
	if err != nil {
		return Status{}, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var v struct {
		State, At, Exe, Args, Next, Last string
		Result                           int
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[len(lines)-1])), &v); err != nil {
		return Status{}, fmt.Errorf("respuesta inesperada del Programador de tareas: %s", strings.TrimSpace(out))
	}
	if v.Exe == "" {
		return Status{}, nil
	}
	st := Status{Enabled: !strings.EqualFold(v.State, "Disabled"), Mechanism: `Programador de tareas (` + taskPath + taskName + `)`,
		At: v.At, Command: `"` + v.Exe + `" ` + v.Args, NextRun: v.Next}
	if v.Last != "" {
		st.Detail = fmt.Sprintf("última ejecución %s, código %d", v.Last, v.Result)
	}
	return st, nil
}
