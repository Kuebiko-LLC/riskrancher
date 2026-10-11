package report

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var UploadDir = "./testdata"

// HandleUploadReport safely receives and stores the pentest file
func (h *Handler) HandleUploadReport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, "Failed to parse form or file too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing 'file' field in upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	cleanName := filepath.Base(header.Filename)
	if cleanName == "." || cleanName == "/" {
		cleanName = "uploaded_report.bin"
	}

	os.MkdirAll(UploadDir, 0755)

	destPath := filepath.Join(UploadDir, cleanName)
	destFile, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to save file to disk", http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, file); err != nil {
		http.Error(w, "Error writing file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"file_id": "%s"}`, cleanName)
}

// HandleViewReport streams the file to the iframe, converting DOCX if needed
func (h *Handler) HandleViewReport(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	cleanName := filepath.Base(fileID)
	filePath := filepath.Join(UploadDir, cleanName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	ext := strings.ToLower(filepath.Ext(cleanName))

	if ext == ".pdf" {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "inline; filename="+cleanName)
		http.ServeFile(w, r, filePath)
		return
	}

	if ext == ".docx" {
		ServeDOCXAsHTML(w, filePath)
		return
	}

	http.Error(w, "Unsupported file type. Please upload PDF or DOCX.", http.StatusBadRequest)
}

func (h *Handler) HandleImageUpload(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Base64Data string `json:"image_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(payload.Base64Data, ",", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid Base64 image format", http.StatusBadRequest)
		return
	}

	ext := ".png"
	if strings.Contains(parts[0], "jpeg") || strings.Contains(parts[0], "jpg") {
		ext = ".jpg"
	}

	rawBase64 := parts[1]
	imgBytes, err := base64.StdEncoding.DecodeString(rawBase64)
	if err != nil {
		http.Error(w, "Failed to decode Base64 data", http.StatusInternalServerError)
		return
	}

	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "Failed to generate filename", http.StatusInternalServerError)
		return
	}
	fileName := fmt.Sprintf("img_%x%s", randBytes, ext)

	uploadDir := filepath.Join("data", "testdata", "images")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Failed to create directory structure", http.StatusInternalServerError)
		return
	}

	savePath := filepath.Join(uploadDir, fileName)
	if err := os.WriteFile(savePath, imgBytes, 0644); err != nil {
		http.Error(w, "Failed to save image to disk", http.StatusInternalServerError)
		return
	}

	publicURL := "/testdata/images/" + fileName

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": publicURL})
}
