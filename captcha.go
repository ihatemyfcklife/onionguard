package onionguard

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/big"
	"strings"
)

var captchaGlyphs = map[byte][7]string{
	'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"},
	'B': {"11110", "10001", "10001", "11110", "10001", "10001", "11110"},
	'C': {"01111", "10000", "10000", "10000", "10000", "10000", "01111"},
	'D': {"11110", "10001", "10001", "10001", "10001", "10001", "11110"},
	'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
	'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
	'G': {"01111", "10000", "10000", "10111", "10001", "10001", "01111"},
	'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"},
	'J': {"00111", "00010", "00010", "00010", "10010", "10010", "01100"},
	'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"},
	'L': {"10000", "10000", "10000", "10000", "10000", "10000", "11111"},
	'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
	'N': {"10001", "11001", "10101", "10011", "10001", "10001", "10001"},
	'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"},
	'Q': {"01110", "10001", "10001", "10001", "10101", "10010", "01101"},
	'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"},
	'S': {"01111", "10000", "10000", "01110", "00001", "00001", "11110"},
	'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
	'U': {"10001", "10001", "10001", "10001", "10001", "10001", "01110"},
	'V': {"10001", "10001", "10001", "10001", "10001", "01010", "00100"},
	'W': {"10001", "10001", "10001", "10101", "10101", "11011", "10001"},
	'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
	'Y': {"10001", "10001", "01010", "00100", "00100", "00100", "00100"},
	'Z': {"11111", "00001", "00010", "00100", "01000", "10000", "11111"},
	'2': {"01110", "10001", "00001", "00010", "00100", "01000", "11111"},
	'3': {"11110", "00001", "00001", "01110", "00001", "00001", "11110"},
	'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
	'5': {"11111", "10000", "10000", "11110", "00001", "00001", "11110"},
	'6': {"01110", "10000", "10000", "11110", "10001", "10001", "01110"},
	'7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
	'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	'9': {"01110", "10001", "10001", "01111", "00001", "00001", "01110"},
}

func randomCaptchaAnswer(alphabet string, length int) (string, error) {
	if length <= 0 || len(alphabet) == 0 {
		return "", ErrInvalidValue
	}
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

func renderCaptchaPNG(answer string, cfg CaptchaConfig) ([]byte, error) {
	if cfg.Visual.CustomGenerator != nil {
		return cfg.Visual.CustomGenerator(answer, cfg.Width, cfg.Height)
	}

	width, height := cfg.Width, cfg.Height
	if width <= 0 || height <= 0 || width > 800 || height > 400 {
		return nil, ErrInvalidValue
	}

	// Resolve colors with defaults.
	bg := cfg.Visual.BackgroundColor
	if bg == nil {
		bg = color.RGBA{R: 245, G: 245, B: 245, A: 255}
	}
	ink := cfg.Visual.TextColor
	if ink == nil {
		ink = color.RGBA{R: 30, G: 30, B: 30, A: 255}
	}
	lineClr := cfg.Visual.LineColor
	if lineClr == nil {
		lineClr = color.RGBA{R: 60, G: 60, B: 60, A: 200}
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)

	scale := height / 10
	if scale < 2 {
		scale = 2
	}
	glyphW := 5 * scale
	spacing := scale
	total := len(answer) * (glyphW + spacing)
	for scale > 1 && total > width {
		scale--
		glyphW = 5 * scale
		spacing = scale
		total = len(answer) * (glyphW + spacing)
	}
	x := (width - total) / 2
	if x < 0 {
		x = 0
	}
	y := (height - 7*scale) / 2
	if y < 0 {
		y = 0
	}

	// Resolve jitter limit.
	jitterLimit := cfg.Visual.JitterPixels
	if jitterLimit <= 0 {
		jitterLimit = 2
	}

	for i := 0; i < len(answer); i++ {
		glyph, ok := captchaGlyphs[answer[i]]
		if !ok {
			continue
		}
		// Per-glyph random vertical jitter for OCR resistance.
		jitterRange := int64(jitterLimit*2 + 1)
		jn, err := rand.Int(rand.Reader, big.NewInt(jitterRange))
		if err != nil {
			return nil, err
		}
		jitter := (int(jn.Int64()) - jitterLimit) * scale

		// Per-glyph slight slant/shear to resist rigid template matching
		sn, err := rand.Int(rand.Reader, big.NewInt(3))
		if err != nil {
			return nil, err
		}
		shear := int(sn.Int64()) - 1

		for ry, row := range glyph {
			shearX := (ry - 3) * shear
			for cx, p := range row {
				if p != '1' {
					continue
				}
				px := x + cx*scale + shearX
				py := y + ry*scale + jitter
				if px >= 0 && px+scale <= width && py >= 0 && py+scale <= height {
					r := image.Rect(px, py, px+scale, py+scale)
					draw.Draw(img, r, &image.Uniform{C: ink}, image.Point{}, draw.Src)
				}
			}
		}
		x += glyphW + spacing
	}

	// Add a non-linear sine wave interference line through the glyphs to disrupt OCR segmentation
	ampR, err := rand.Int(rand.Reader, big.NewInt(4))
	if err != nil {
		return nil, err
	}
	amp := float64(ampR.Int64() + 3)
	freqR, err := rand.Int(rand.Reader, big.NewInt(4))
	if err != nil {
		return nil, err
	}
	freq := 0.06 + float64(freqR.Int64())*0.02
	phaseR, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		return nil, err
	}
	phase := float64(phaseR.Int64())
	midY := float64(height) / 2.0
	for wx := 0; wx < width; wx++ {
		wy := int(midY + amp*math.Sin(float64(wx)*freq+phase))
		if wy >= 0 && wy < height {
			img.Set(wx, wy, lineClr)
			if wy+1 < height {
				img.Set(wx, wy+1, lineClr)
			}
		}
	}

	// Configurable diagonal noise lines.
	linesCount := cfg.Visual.NoiseLines
	if linesCount < 0 {
		linesCount = 2
	} else if linesCount == 0 && cfg.Visual.NoiseRatio == 0 && cfg.Visual.JitterPixels == 0 && cfg.Visual.BackgroundColor == nil && cfg.Visual.TextColor == nil && cfg.Visual.LineColor == nil {
		// Zero-value default configuration
		linesCount = 2
	}
	for l := 0; l < linesCount; l++ {
		x1r, err := rand.Int(rand.Reader, big.NewInt(int64(width)))
		if err != nil {
			return nil, err
		}
		y1r, err := rand.Int(rand.Reader, big.NewInt(int64(height)))
		if err != nil {
			return nil, err
		}
		x2r, err := rand.Int(rand.Reader, big.NewInt(int64(width)))
		if err != nil {
			return nil, err
		}
		y2r, err := rand.Int(rand.Reader, big.NewInt(int64(height)))
		if err != nil {
			return nil, err
		}
		drawLine(img, int(x1r.Int64()), int(y1r.Int64()), int(x2r.Int64()), int(y2r.Int64()), lineClr)
	}

	// Configurable pixel noise density.
	ratio := cfg.Visual.NoiseRatio
	if ratio <= 0 {
		ratio = 0.02
	}
	noise := int(float64(width*height) * ratio)
	if noise > 5000 {
		noise = 5000
	}
	for i := 0; i < noise; i++ {
		px, err := rand.Int(rand.Reader, big.NewInt(int64(width)))
		if err != nil {
			return nil, err
		}
		py, err := rand.Int(rand.Reader, big.NewInt(int64(height)))
		if err != nil {
			return nil, err
		}
		img.Set(int(px.Int64()), int(py.Int64()), lineClr)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func captchaDataURI(pngData []byte) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngData)
}

func RenderCaptchaHTML(ch *CaptchaChallenge, cfg CaptchaConfig) string {
	return RenderCaptchaHTMLWithTarget(ch, cfg, "")
}

// RenderCaptchaHTMLWithTarget returns a zero-JavaScript CAPTCHA challenge HTML page
// preserving the sanitized target URL across the form submission.
func RenderCaptchaHTMLWithTarget(ch *CaptchaChallenge, cfg CaptchaConfig, target string) string {
	if ch == nil {
		return ""
	}
	targetField := ""
	if target != "" {
		targetField = fmt.Sprintf(`<input type="hidden" name="target" value="%s">`, html.EscapeString(target))
	}
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"><title>Challenge</title></head><body><main><h1>Verification</h1><img alt="CAPTCHA" src="%s"><form method="post" action="%s">%s<label for="answer">Answer</label><input id="answer" name="answer" maxlength="%d" required autocomplete="off"><button type="submit">Continue</button></form></main></body></html>`, ch.ImageDataURI, html.EscapeString(cfg.EndpointPath), targetField, cfg.Length)
}

// drawLine renders a 1-pixel line between two points using Bresenham's algorithm.
func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	dx := x1 - x0
	dy := y1 - y0
	if dx < 0 {
		dx = -dx
	}
	if dy < 0 {
		dy = -dy
	}
	sx := 1
	if x0 >= x1 {
		sx = -1
	}
	sy := 1
	if y0 >= y1 {
		sy = -1
	}
	err := dx - dy
	for {
		img.Set(x0, y0, c)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}
