// Package selfupdate actualiza el binario de Bastion desde las releases de
// GitHub (o un espejo interno) verificando la suma SHA-256 publicada.
//
// Contrato de releases (lo cumple GitHub y cualquier espejo estático):
//
//	<base>/latest/download/version.txt         → etiqueta de la última versión
//	<base>/download/<tag>/checksums.txt        → sumas SHA-256
//	<base>/download/<tag>/bastion_<os>_<arch>.tar.gz | .zip
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/version"
)

const maxDownload = 200 << 20 // 200 MiB

// Source indica de dónde se descargan las releases.
type Source struct {
	Repo    string // owner/nombre en GitHub
	BaseURL string // espejo opcional; por defecto https://github.com/<repo>/releases
}

// Base devuelve la URL base de releases.
func (s Source) Base() string {
	if s.BaseURL != "" {
		return strings.TrimRight(s.BaseURL, "/")
	}
	return "https://github.com/" + s.Repo + "/releases"
}

var client = &http.Client{Timeout: 5 * time.Minute}

func get(ctx context.Context, url string, w io.Writer, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "bastion/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("GET %s: respuesta demasiado grande", url)
	}
	return nil
}

// Latest devuelve la etiqueta de la última versión publicada.
func (s Source) Latest(ctx context.Context) (string, error) {
	var b strings.Builder
	if err := get(ctx, s.Base()+"/latest/download/version.txt", &b, 256); err != nil {
		return "", err
	}
	tag := strings.TrimSpace(b.String())
	if tag == "" || strings.ContainsAny(tag, "/ \\") {
		return "", fmt.Errorf("version.txt inválido: %q", tag)
	}
	return tag, nil
}

// AssetName es el nombre del archivo de release para una plataforma.
func AssetName(goos, goarch string) string {
	if goos == "windows" {
		return fmt.Sprintf("bastion_%s_%s.zip", goos, goarch)
	}
	return fmt.Sprintf("bastion_%s_%s.tar.gz", goos, goarch)
}

// Download descarga y verifica la release tag y devuelve la ruta del binario
// extraído en un directorio temporal (que el llamador debe borrar).
func (s Source) Download(ctx context.Context, tag string) (binPath, tmpDir string, err error) {
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	tmpDir, err = os.MkdirTemp("", "bastion-update-")
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmpDir)
			tmpDir = ""
		}
	}()

	var sums strings.Builder
	if err = get(ctx, fmt.Sprintf("%s/download/%s/checksums.txt", s.Base(), tag), &sums, 1<<20); err != nil {
		return "", "", err
	}
	want, ok := ParseChecksums(sums.String())[asset]
	if !ok {
		return "", "", fmt.Errorf("checksums.txt no contiene %s", asset)
	}

	archive := filepath.Join(tmpDir, asset)
	f, err := os.Create(archive)
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	err = get(ctx, fmt.Sprintf("%s/download/%s/%s", s.Base(), tag, asset), io.MultiWriter(f, h), maxDownload)
	f.Close()
	if err != nil {
		return "", "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		return "", "", fmt.Errorf("la suma SHA-256 no coincide (esperada %s, obtenida %s): descarga abortada", want, got)
	}

	exe := "bastion"
	if runtime.GOOS == "windows" {
		exe = "bastion.exe"
	}
	binPath = filepath.Join(tmpDir, exe+".new")
	if strings.HasSuffix(asset, ".zip") {
		err = extractZip(archive, exe, binPath)
	} else {
		err = extractTarGz(archive, exe, binPath)
	}
	return binPath, tmpDir, err
}

// ParseChecksums interpreta un checksums.txt ("<sha256>  <fichero>").
func ParseChecksums(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && len(f[0]) == 64 {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out
}

func extractTarGz(archive, name, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("el archivo no contiene %s", name)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == name {
			return writeExec(dst, io.LimitReader(tr, maxDownload))
		}
	}
}

func extractZip(archive, name, dst string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if filepath.Base(f.Name) == name && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return writeExec(dst, io.LimitReader(rc, maxDownload))
		}
	}
	return fmt.Errorf("el archivo no contiene %s", name)
}

func writeExec(dst string, r io.Reader) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Apply sustituye el ejecutable actual por newBin.
// En Linux el reemplazo es atómico (rename). En Windows un ejecutable en uso
// no se puede sobrescribir pero sí renombrar: se mueve a .old y se borra en
// el siguiente arranque (CleanupOld).
func Apply(newBin string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	staged := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	if err := copyFile(newBin, staged); err != nil {
		return fmt.Errorf("no se pudo escribir en %s (¿permisos de administrador?): %w", dir, err)
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			os.Remove(staged)
			return err
		}
		if err := os.Rename(staged, exe); err != nil {
			os.Rename(old, exe) // deshacer
			return err
		}
		return nil
	}
	return os.Rename(staged, exe)
}

// InstallDirWritable comprueba si se puede escribir junto al ejecutable
// actual (lo que necesita Apply). Devuelve el directorio y el error.
func InstallDirWritable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".bastion-write-test-*")
	if err != nil {
		return dir, err
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return dir, nil
}

// CleanupOld elimina el ejecutable anterior que deja Apply en Windows.
func CleanupOld() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeExec(dst, in)
}

// Newer indica si latest es una versión posterior a current. Las versiones
// de desarrollo ("dev") nunca se consideran anteriores.
func Newer(latest, current string) bool {
	l, okL := parseSemver(latest)
	c, okC := parseSemver(current)
	if !okL || !okC {
		return false
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	// Misma versión: una final es posterior a una pre-release.
	return l[3] == 0 && c[3] == 1
}

// parseSemver devuelve [mayor, menor, parche, esPrerelease].
func parseSemver(v string) ([4]int, bool) {
	var out [4]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		if v[i] == '-' {
			out[3] = 1
		}
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
