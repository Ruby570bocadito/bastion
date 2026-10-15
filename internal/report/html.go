package report

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/tu-usuario/bastion/internal/engine"
)

//go:embed assets/report.html
var htmlTemplate []byte

// HTML genera un informe autocontenido (un único fichero, sin dependencias
// externas) que funciona sin conexión y se puede enviar por correo.
//
// Seguridad: los datos del escaneo proceden del sistema auditado y podrían
// contener texto malicioso (p. ej. una línea de sudoers manipulada). Por eso
//   - se serializan con encoding/json, que escapa <, > y & (no puede cerrar
//     la etiqueta <script>);
//   - el JavaScript los inserta siempre con textContent, nunca como HTML;
//   - la página declara una CSP que solo ejecuta el script con el nonce
//     aleatorio de este informe y bloquea cualquier carga externa.
func HTML(w io.Writer, rep *engine.Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := bytes.ReplaceAll(htmlTemplate, []byte("__NONCE__"), []byte(base64.RawURLEncoding.EncodeToString(nonce)))
	out = bytes.Replace(out, []byte("__BASTION_DATA__"), data, 1)
	_, err = w.Write(out)
	return err
}
