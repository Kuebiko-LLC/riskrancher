package evidence_test

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pro/evidence"
)

func makePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		img.Set(x, 0, color.RGBA{uint8(x), 0, 0, 255})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func makeJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

func TestProcessBoundsLargeImage(t *testing.T) {
	p, err := evidence.Process(makePNG(t, 3000, 1500))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if p.Width != 1600 {
		t.Errorf("expected web width bounded to 1600, got %d", p.Width)
	}
	if p.Height != 800 {
		t.Errorf("expected web height 800 (aspect kept), got %d", p.Height)
	}
	if p.ContentType != "image/png" {
		t.Errorf("expected png content type, got %q", p.ContentType)
	}
	// thumbnail must be strictly smaller than the web image
	tw, th := decodeDims(t, p.Thumb)
	if tw > 320 || th > 320 {
		t.Errorf("thumbnail should be bounded to 320, got %dx%d", tw, th)
	}
	if len(p.Thumb) >= len(p.Web) {
		t.Errorf("thumbnail should be smaller than the web image")
	}
}

func TestProcessKeepsSmallImageAndStripsMetadata(t *testing.T) {
	raw := makePNG(t, 100, 80)
	p, err := evidence.Process(raw)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if p.Width != 100 || p.Height != 80 {
		t.Errorf("small image should keep its size, got %dx%d", p.Width, p.Height)
	}
	// It is re-encoded (metadata stripped), so it still decodes cleanly.
	if _, _, err := image.Decode(bytes.NewReader(p.Web)); err != nil {
		t.Errorf("re-encoded web image should decode: %v", err)
	}
}

func TestProcessJPEGStaysJPEG(t *testing.T) {
	p, err := evidence.Process(makeJPEG(t, 2000, 2000))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if p.ContentType != "image/jpeg" {
		t.Errorf("jpeg should stay jpeg, got %q", p.ContentType)
	}
	if p.Width != 1600 || p.Height != 1600 {
		t.Errorf("expected 1600x1600, got %dx%d", p.Width, p.Height)
	}
}

func TestProcessRejectsNonImage(t *testing.T) {
	if _, err := evidence.Process([]byte("not an image")); err == nil {
		t.Errorf("expected an error for non-image bytes")
	}
}

func decodeDims(t *testing.T, raw []byte) (int, int) {
	t.Helper()
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return cfg.Width, cfg.Height
}
