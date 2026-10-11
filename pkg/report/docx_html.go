package report

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

// Relationships maps the pkg rId to the actual media file
type Relationships struct {
	XMLName xml.Name `xml:"Relationships"`
	Rel     []struct {
		Id     string `xml:"Id,attr"`
		Target string `xml:"Target,attr"`
	} `xml:"Relationship"`
}

func ServeDOCXAsHTML(w http.ResponseWriter, docxPath string) {
	r, err := zip.OpenReader(docxPath)
	if err != nil {
		http.Error(w, "Failed to open DOCX archive", http.StatusInternalServerError)
		return
	}
	defer r.Close()

	relsMap := make(map[string]string)
	for _, f := range r.File {
		if f.Name == "word/_rels/document.xml.rels" {
			rc, _ := f.Open()
			var rels Relationships
			xml.NewDecoder(rc).Decode(&rels)
			rc.Close()
			for _, rel := range rels.Rel {
				relsMap[rel.Id] = rel.Target
			}
			break
		}
	}

	mediaMap := make(map[string]string)
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "word/media/") {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()

			ext := strings.TrimPrefix(filepath.Ext(f.Name), ".")
			if ext == "jpeg" || ext == "jpg" {
				ext = "jpeg"
			}
			b64 := base64.StdEncoding.EncodeToString(data)
			mediaMap[f.Name] = fmt.Sprintf("data:image/%s;base64,%s", ext, b64)
		}
	}

	var htmlOutput bytes.Buffer
	var inParagraph bool

	for _, f := range r.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			decoder := xml.NewDecoder(rc)

			for {
				token, err := decoder.Token()
				if err != nil {
					break
				}

				switch se := token.(type) {
				case xml.StartElement:
					if se.Name.Local == "p" {
						htmlOutput.WriteString("<p style='margin-bottom: 10px;'>")
						inParagraph = true
					}
					if se.Name.Local == "t" {
						var text string
						decoder.DecodeElement(&text, &se)
						htmlOutput.WriteString(text)
					}
					if se.Name.Local == "blip" {
						for _, attr := range se.Attr {
							if attr.Name.Local == "embed" {
								targetPath := relsMap[attr.Value]
								fullMediaPath := "word/" + targetPath

								if b64URI, exists := mediaMap[fullMediaPath]; exists {
									imgTag := fmt.Sprintf(`<br><img src="%s" style="max-width: 100%%; height: auto; border: 1px solid #cbd5e1; border-radius: 4px; margin: 15px 0; cursor: pointer;" class="pentest-img" title="Click to extract image"><br>`, b64URI)
									htmlOutput.WriteString(imgTag)
								}
							}
						}
					}
				case xml.EndElement:
					if se.Name.Local == "p" && inParagraph {
						htmlOutput.WriteString("</p>\n")
						inParagraph = false
					}
				}
			}
			rc.Close()
			break
		}
	}

	w.Write(htmlOutput.Bytes())
}
