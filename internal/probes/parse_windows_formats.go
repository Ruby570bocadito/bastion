package probes

// Parsers puros de formatos de Windows, separados para poder probarlos en
// cualquier plataforma.

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
)

// parseSecpolINF interpreta el INF que genera "secedit /export".
// Devuelve sección → clave → valor (claves en su forma original).
func parseSecpolINF(text string) map[string]map[string]string {
	out := map[string]map[string]string{}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if out[section] == nil {
				out[section] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		out[section][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

// secpolValue convierte un valor del INF al tipo adecuado: número, lista de
// SIDs (Privilege Rights) o texto. En "Registry Values" el formato es
// "tipo,valor" (p. ej. "4,1").
func secpolValue(section, raw string) any {
	switch section {
	case "privilege rights":
		var sids []any
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimPrefix(strings.TrimSpace(s), "*")
			if s != "" {
				sids = append(sids, s)
			}
		}
		return sids
	case "registry values":
		if _, v, ok := strings.Cut(raw, ","); ok {
			raw = v
		}
	}
	raw = strings.Trim(raw, `"`)
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n
	}
	return raw
}

// parseAuditpolBackup interpreta el CSV de "auditpol /backup". Devuelve
// GUID de subcategoría (en minúsculas, sin llaves) → nombre y valor numérico
// (0 sin auditoría, 1 aciertos, 2 errores, 3 ambos). Se usa el valor numérico
// porque los textos ("Success and Failure") dependen del idioma de Windows.
func parseAuditpolBackup(text string) (map[string]auditSetting, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV de auditpol inválido: %w", err)
	}
	out := map[string]auditSetting{}
	guidCol, nameCol, valCol := -1, -1, -1
	for i, row := range rows {
		if i == 0 {
			for j, h := range row {
				switch strings.ToLower(strings.TrimSpace(h)) {
				case "subcategory guid":
					guidCol = j
				case "subcategory":
					nameCol = j
				case "setting value":
					valCol = j
				}
			}
			if guidCol < 0 || valCol < 0 {
				// Cabecera localizada: usamos las posiciones estándar.
				nameCol, guidCol, valCol = 2, 3, 6
			}
			continue
		}
		if len(row) <= valCol || len(row) <= guidCol {
			continue
		}
		guid := normGUID(row[guidCol])
		if guid == "" {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(row[valCol]))
		if err != nil {
			continue
		}
		name := ""
		if nameCol >= 0 && nameCol < len(row) {
			name = row[nameCol]
		}
		out[guid] = auditSetting{Name: name, Value: v}
	}
	return out, nil
}

type auditSetting struct {
	Name  string
	Value int
}

func normGUID(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
}

// splitRegistryPath separa "HKLM\SOFTWARE\x" en raíz ("HKLM") y subruta.
func splitRegistryPath(p string) (root, sub string, err error) {
	p = strings.ReplaceAll(p, "/", `\`)
	root, sub, _ = strings.Cut(p, `\`)
	switch strings.ToUpper(root) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "HKLM", sub, nil
	case "HKU", "HKEY_USERS":
		return "HKU", sub, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return "HKCR", sub, nil
	}
	return "", "", fmt.Errorf("raíz de registro no soportada: %q (usa HKLM, HKU o HKCR)", root)
}
