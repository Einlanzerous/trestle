package sniff

import "encoding/binary"

// ftypBrands reads the ftyp box an ISO-BMFF file starts with: a 32-bit size,
// "ftyp", the major brand, a minor version, then compatible brands to the end
// of the box. ok reports whether head starts with an ftyp box at all; a
// malformed one comes back with ok true and an empty major brand, so it is
// refused rather than sniffed some other way.
func ftypBrands(head []byte) (major string, compat []string, ok bool) {
	if len(head) < 8 || string(head[4:8]) != "ftyp" {
		return "", nil, false
	}
	size := binary.BigEndian.Uint32(head[:4])
	// 0 ("to end of file") and 1 (a 64-bit size follows) are legal box sizes
	// but never an ftyp's; anything under 16 cannot hold a major brand.
	if size < 16 || size%4 != 0 || len(head) < 16 {
		return "", nil, true
	}
	end := min(int(size), len(head))
	for i := 16; i+4 <= end; i += 4 {
		compat = append(compat, string(head[i:i+4]))
	}
	return string(head[8:12]), compat, true
}

// fromBrands maps ftyp brands to a type. The major brand decides; only the
// generic HEIF structural brands (mif1 for images, msf1 for sequences) look
// at the compatible brands to see what codec the file declares.
//
//   - heic, heix, hevc, hevx → image/heic (HEVC-coded HEIF; the sequence
//     brands are labelled image/heic too, since one type per codec is all a
//     photo library needs)
//   - avif, avis → image/avif
//   - "qt  " → video/quicktime
//   - mif1/msf1 → image/heic when the compatible brands declare HEVC and not
//     AV1, image/avif when they declare AV1 and not HEVC, otherwise
//     image/heif (no codec brand, or both: the generic container type is
//     the only honest label)
//
// Anything else is not recognised. mp4 never reaches here: it is decided
// by the v1 check before the brand table runs.
func fromBrands(major string, compat []string) (Type, bool) {
	switch major {
	case "heic", "heix", "hevc", "hevx":
		return HEIC, true
	case "avif", "avis":
		return AVIF, true
	case "qt  ":
		return QuickTime, true
	case "mif1", "msf1":
		var hevc, av1 bool
		for _, b := range compat {
			switch b {
			case "heic", "heix", "hevc", "hevx":
				hevc = true
			case "avif", "avis":
				av1 = true
			}
		}
		switch {
		case hevc && !av1:
			return HEIC, true
		case av1 && !hevc:
			return AVIF, true
		default:
			return HEIF, true
		}
	}
	return Type{}, false
}
