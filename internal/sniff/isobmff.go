package sniff

import (
	"encoding/binary"
	"slices"
)

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
//   - a 3GPP brand (threeGPP) → video/3gpp; a 3GPP2 brand (threeGPP2) →
//     video/3gpp2 (GENZO-26). As the major brand it decides like any other.
//     Only when the major brand is none of the above are the compatible
//     brands consulted: any 3GPP2 brand → video/3gpp2, else any 3GPP brand
//     → video/3gpp (3GPP2 files commonly list a 3GPP brand too, so the
//     narrower 3GPP2 family wins). A generic major brand such as isom with no
//     3GPP brand anywhere stays unrecognised.
//
// Anything else is not recognised. mp4 never reaches here: it is decided
// by the v1 check before the brand table runs, so a 3G2 that lists mp42
// stays video/mp4, as it was before GENZO-26.
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
	switch {
	case threeGPP2[major]:
		return ThreeGPP2, true
	case threeGPP[major]:
		return ThreeGPP, true
	case slices.ContainsFunc(compat, func(b string) bool { return threeGPP2[b] }):
		return ThreeGPP2, true
	case slices.ContainsFunc(compat, func(b string) bool { return threeGPP[b] }):
		return ThreeGPP, true
	}
	return Type{}, false
}

// threeGPP is the 3GPP brands that mark a whole 3GP presentation, from the
// MP4 registration authority's brand list (mp4ra.org): the release brands
// 3gp4–3gp9, the Release 6–9 profile brands, 3gtv (TV over 3GPP) and 3gvr
// (VR presentation). Left out: 3gh9, 3gm9 and
// 3gmA, which mark adaptive-streaming init and media segments rather than a
// playable file.
var threeGPP = map[string]bool{
	"3gp4": true, "3gp5": true, "3gp6": true, "3gp7": true, "3gp8": true, "3gp9": true,
	"3ge6": true, "3ge7": true, "3ge9": true,
	"3gg6": true, "3gg9": true,
	"3gr6": true, "3gr9": true,
	"3gs6": true, "3gs9": true,
	"3gt8": true, "3gt9": true,
	"3gf9": true, "3gtv": true, "3gvr": true,
}

// threeGPP2 is the 3GPP2 brands: 3g2a (registered at mp4ra.org) and 3g2b,
// 3g2c, defined by later revisions of 3GPP2 C.S0050.
var threeGPP2 = map[string]bool{"3g2a": true, "3g2b": true, "3g2c": true}
