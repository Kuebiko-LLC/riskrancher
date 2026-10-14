package report

import (
	"archive/zip"
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A report is a document someone else wrote. Its text is shown as text,
// never run as markup.
func TestDocxToHTML_EscapesText(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	doc, _ := zw.Create("word/document.xml")
	doc.Write([]byte(`<w:document><w:body><w:p><w:r><w:t>&lt;script&gt;alert("xss")&lt;/script&gt; 1 &lt; 2</w:t></w:r></w:p></w:body></w:document>`))
	zw.Close()
	path := filepath.Join(t.TempDir(), "hostile.docx")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ServeDOCXAsHTML(rec, path)
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("report text rendered as markup: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "1 &lt; 2") {
		t.Fatalf("report text must be shown escaped: %s", body)
	}
}
