package xfer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"
)

// Source is a set of local files prepared for sending.
type Source struct {
	Offer   Offer
	Local   []string      // absolute local path of each Offer.Files entry
	infos   []fs.FileInfo // what each file was when listed
	Total   int64         // sum of file sizes
	Skipped []string      // symlinks and special files that are not sent
}

// Collect walks the given paths and builds the offer. Each argument is sent
// under its base name; directories are sent recursively. Symbolic links
// inside directories and special files (devices, sockets, pipes) are skipped
// and listed in Skipped. A symbolic link given directly as an argument is
// followed.
func Collect(paths []string) (*Source, error) {
	if len(paths) == 0 {
		return nil, errors.New("nothing to send")
	}
	src := &Source{}
	top := map[string]string{}
	for _, arg := range paths {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(abs)
		if name == string(filepath.Separator) || name == "." || filepath.VolumeName(abs)+string(filepath.Separator) == abs {
			return nil, fmt.Errorf("%s: can't send a whole drive or the root folder; pick a folder inside it", arg)
		}
		if prev, ok := top[foldKey(name)]; ok {
			return nil, fmt.Errorf("%s and %s have the same name %q; rename one or send them separately", prev, arg, name)
		}
		top[foldKey(name)] = arg

		// Follow a symlink given as an argument: the user named it.
		real, err := filepath.EvalSymlinks(abs)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: no such file or folder", arg)
		}
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(real)
		if err != nil {
			return nil, err
		}
		switch {
		case info.Mode().IsRegular():
			if err := src.addFile(real, name, info); err != nil {
				return nil, err
			}
		case info.IsDir():
			if err := src.addDir(real, name); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%s: not a regular file or folder", arg)
		}
	}
	if _, err := validateOffer(&src.Offer); err != nil {
		return nil, err
	}
	return src, nil
}

func (s *Source) addFile(abs, rel string, info fs.FileInfo) error {
	if err := ValidatePath(rel); err != nil {
		return fmt.Errorf("can't send %s: %w", abs, err)
	}
	if IsPartName(rel) {
		return fmt.Errorf("can't send %s: names ending in %s are reserved for partial downloads", abs, PartSuffix)
	}
	if len(s.Offer.Files) >= MaxFiles {
		return fmt.Errorf("too many files (limit %d)", MaxFiles)
	}
	s.Offer.Files = append(s.Offer.Files, File{
		Path:  rel,
		Size:  info.Size(),
		Exec:  info.Mode().Perm()&0o111 != 0,
		MTime: info.ModTime().UnixNano(),
	})
	s.Local = append(s.Local, abs)
	s.infos = append(s.infos, info)
	s.Total += info.Size()
	return nil
}

func (s *Source) addDir(root, name string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = path.Join(name, filepath.ToSlash(rel))
		switch {
		case d.IsDir():
			if err := ValidatePath(rel); err != nil {
				return fmt.Errorf("can't send %s: %w", p, err)
			}
			s.Offer.Dirs = append(s.Offer.Dirs, rel)
			return nil
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			return s.addFile(p, rel, info)
		default:
			s.Skipped = append(s.Skipped, p)
			return nil
		}
	})
}

// open opens file i for reading, refusing it if it is no longer the regular
// file that was listed (for example if someone replaced it with a symlink
// to another file, or with a pipe).
func (s *Source) open(i int) (*os.File, error) {
	changed := &fileChangedError{s.Offer.Files[i].Path}
	f, err := os.OpenFile(s.Local[i], os.O_RDONLY|openFlags, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || isSymlinkErr(err) {
			return nil, changed
		}
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() || (s.infos != nil && !os.SameFile(st, s.infos[i])) {
		f.Close()
		return nil, changed
	}
	return f, nil
}

// isSymlinkErr reports the error open(2) gives for O_NOFOLLOW on a symlink.
func isSymlinkErr(err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe) && (pe.Err == syscall.ELOOP || pe.Err == syscall.EMLINK)
}
