package rule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog contiene las reglas y perfiles cargados de uno o varios paquetes.
type Catalog struct {
	Rules    []*Rule
	Profiles map[string]*Profile
	byID     map[string]*Rule
}

// NewCatalog crea un catálogo vacío.
func NewCatalog() *Catalog {
	return &Catalog{Profiles: map[string]*Profile{}, byID: map[string]*Rule{}}
}

// LoadFS carga todos los .yaml/.yml de fsys. Los ficheros bajo un directorio
// "profiles" son perfiles; el resto son reglas. Un fichero puede contener
// varios documentos separados por "---". origin se antepone a Source.
func (c *Catalog) LoadFS(fsys fs.FS, origin string) error {
	var errs []error
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "schema" {
				return fs.SkipDir
			}
			return nil
		}
		ext := path.Ext(p)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		src := origin + p
		isProfile := strings.HasPrefix(p, "profiles/") || strings.Contains(p, "/profiles/")
		if err := c.loadFile(data, src, isProfile); err != nil {
			errs = append(errs, err)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// LoadDir carga reglas de un directorio del disco (p. ej. rules.d).
// Si el directorio no existe no es un error.
func (c *Catalog) LoadDir(dir string) error {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil
	}
	return c.LoadFS(os.DirFS(dir), dir+string(os.PathSeparator))
}

func (c *Catalog) loadFile(data []byte, src string, isProfile bool) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	for i := 0; ; i++ {
		if isProfile {
			var p Profile
			err := dec.Decode(&p)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("%s (documento %d): %w", src, i+1, err)
			}
			if p.ID == "" {
				continue
			}
			if _, dup := c.Profiles[p.ID]; dup {
				return fmt.Errorf("%s: perfil duplicado %q", src, p.ID)
			}
			p.Source = src
			c.Profiles[p.ID] = &p
			continue
		}
		var r Rule
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s (documento %d): %w", src, i+1, err)
		}
		if r.ID == "" && r.Title == "" {
			continue // documento vacío
		}
		if _, dup := c.byID[r.ID]; dup {
			return fmt.Errorf("%s: regla duplicada %q (ya definida en %s)", src, r.ID, c.byID[r.ID].Source)
		}
		r.Source = src
		c.Rules = append(c.Rules, &r)
		c.byID[r.ID] = &r
	}
}

// Rule devuelve la regla con ese ID.
func (c *Catalog) Rule(id string) *Rule { return c.byID[strings.ToUpper(id)] }

// Validate valida todas las reglas y perfiles. Devuelve un error por problema.
func (c *Catalog) Validate(knownProbes map[string]bool) []error {
	var errs []error
	for _, p := range c.sortedProfiles() {
		if p.Name == "" {
			errs = append(errs, fmt.Errorf("perfil %s: name vacío", p.ID))
		}
		for _, e := range p.Extends {
			if c.Profiles[e] == nil {
				errs = append(errs, fmt.Errorf("perfil %s: extends %q no existe", p.ID, e))
			}
		}
		for _, pl := range append(append([]string{}, p.Platforms...), p.DefaultFor...) {
			if !Platforms[pl] {
				errs = append(errs, fmt.Errorf("perfil %s: platform %q desconocida", p.ID, pl))
			}
		}
	}
	for _, r := range c.Rules {
		for _, e := range r.Validate(knownProbes, c.Profiles) {
			errs = append(errs, fmt.Errorf("%s [%s]: %w", r.ID, r.Source, e))
		}
	}
	return errs
}

// Lineage devuelve el perfil y todos sus ancestros (extends), sin ciclos.
func (c *Catalog) Lineage(profileID string) map[string]bool {
	out := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		if out[id] {
			return
		}
		p := c.Profiles[id]
		if p == nil {
			return
		}
		out[id] = true
		for _, e := range p.Extends {
			walk(e)
		}
	}
	walk(profileID)
	return out
}

// Select devuelve las reglas aplicables a las etiquetas del equipo y al perfil.
func (c *Catalog) Select(hostTags []string, profileID string) []*Rule {
	lineage := c.Lineage(profileID)
	var out []*Rule
	for _, r := range c.Rules {
		if !MatchesPlatform(r.Platforms, hostTags) {
			continue
		}
		in := false
		for _, p := range r.Profiles {
			if lineage[p] {
				in = true
				break
			}
		}
		if in {
			out = append(out, r)
		}
	}
	SortRules(out)
	return out
}

// DefaultProfile elige el perfil por defecto para el equipo. hostTags debe ir
// de la etiqueta más específica a la más general (p. ej. windows-dc antes
// que windows-server).
func (c *Catalog) DefaultProfile(hostTags []string) *Profile {
	for _, t := range hostTags {
		for _, p := range c.sortedProfiles() {
			for _, d := range p.DefaultFor {
				if d == t {
					return p
				}
			}
		}
	}
	return nil
}

// ProfilesFor devuelve los perfiles compatibles con el equipo.
func (c *Catalog) ProfilesFor(hostTags []string) []*Profile {
	var out []*Profile
	for _, p := range c.sortedProfiles() {
		if hostTags == nil || MatchesPlatform(p.Platforms, hostTags) {
			out = append(out, p)
		}
	}
	return out
}

func (c *Catalog) sortedProfiles() []*Profile {
	out := make([]*Profile, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
