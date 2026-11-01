package xfer

import (
	"path"
	"strings"
)

// Things in an offer that deserve the receiver's attention before saying
// yes, because a hostile sender could use them to run code on the
// receiver's machine (an autostart entry, a shell profile, a git hook...).

// sensitiveNames are folders that hold keys or run code when used, and that
// the receiver must explicitly accept (croc refuses them outright).
var sensitiveNames = map[string]bool{".ssh": true, ".gnupg": true, ".git": true}

// Sensitive returns, for every path in the offer that goes through a
// sensitive folder (.ssh, .gnupg, .git), that folder's path, each once.
func Sensitive(o *Offer) []string {
	var out []string
	seen := map[string]bool{}
	check := func(p string) {
		parts := strings.Split(p, "/")
		for i, part := range parts {
			if sensitiveNames[strings.ToLower(caseFold(part))] {
				prefix := strings.Join(parts[:i+1], "/")
				if !seen[prefix] {
					seen[prefix] = true
					out = append(out, prefix)
				}
				return
			}
		}
	}
	for _, f := range o.Files {
		check(f.Path)
	}
	for _, d := range o.Dirs {
		check(d)
	}
	return out
}

// runnableExt are extensions Windows, macOS or Linux desktops run when the
// file is opened.
var runnableExt = map[string]bool{
	".exe": true, ".com": true, ".bat": true, ".cmd": true, ".ps1": true, ".psm1": true,
	".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".wsh": true,
	".hta": true, ".msi": true, ".msp": true, ".scr": true, ".pif": true, ".cpl": true,
	".lnk": true, ".reg": true, ".jar": true, ".desktop": true, ".command": true,
	".appimage": true, ".sh": true,
}

// Executables returns the files in the offer that are marked executable or
// have an extension that runs when opened.
func Executables(o *Offer) []string {
	var out []string
	for _, f := range o.Files {
		if f.Exec || runnableExt[strings.ToLower(path.Ext(f.Path))] {
			out = append(out, f.Path)
		}
	}
	return out
}
