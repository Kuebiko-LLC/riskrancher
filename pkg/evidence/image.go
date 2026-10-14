// Package evidence processes uploaded screenshots/images for pentest findings:
// it re-encodes (which drops EXIF and any embedded metadata), bounds them to a
// web-friendly size, and makes a thumbnail. Pure Go, no CGO, so the single
// binary stays clean and air-gapped.
package evidence

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"image/png"

	_ "image/gif"  // register GIF decoder
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder

	xdraw "golang.org/x/image/draw"
)

// ErrUnsupportedImage is returned when the upload is not a decodable image.
var ErrUnsupportedImage = errors.New("unsupported or corrupt image")

const (
	maxWebDim   = 1600 // longest side of the embedded/web image
	maxThumbDim = 320  // longest side of the thumbnail
	jpegQuality = 85
)

// Processed holds the re-encoded web image and thumbnail plus the web image's
// dimensions and served content type.
type Processed struct {
	Web         []byte
	Thumb       []byte
	Width       int
	Height      int
	ContentType string
}

// Process decodes raw image bytes and returns a bounded web image + thumbnail.
// Re-encoding strips EXIF/metadata. PNG/GIF are emitted as PNG (lossless, good
// for screenshots with text); JPEG stays JPEG.
func Process(raw []byte) (*Processed, error) {
	img, format, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrUnsupportedImage
	}

	asJPEG := format == "jpeg"
	web := scaleToBound(img, maxWebDim)
	thumb := scaleToBound(img, maxThumbDim)

	webBytes, ct, err := encode(web, asJPEG)
	if err != nil {
		return nil, err
	}
	thumbBytes, _, err := encode(thumb, asJPEG)
	if err != nil {
		return nil, err
	}

	b := web.Bounds()
	return &Processed{
		Web:         webBytes,
		Thumb:       thumbBytes,
		Width:       b.Dx(),
		Height:      b.Dy(),
		ContentType: ct,
	}, nil
}

// boundedSize returns dimensions scaled so the longest side is at most max,
// preserving aspect ratio. Images already within the bound are unchanged.
func boundedSize(w, h, max int) (int, int) {
	if w <= max && h <= max {
		return w, h
	}
	if w >= h {
		return max, h*max/w + boolToInt(h*max%w != 0)
	}
	return w*max/h + boolToInt(w*max%h != 0), max
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scaleToBound(src image.Image, max int) image.Image {
	b := src.Bounds()
	nw, nh := boundedSize(b.Dx(), b.Dy(), max)
	if nw == b.Dx() && nh == b.Dy() {
		return src
	}
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, b, xdraw.Over, nil)
	return dst
}

func encode(img image.Image, asJPEG bool) ([]byte, string, error) {
	var buf bytes.Buffer
	if asJPEG {
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "image/jpeg", nil
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "image/png", nil
}
