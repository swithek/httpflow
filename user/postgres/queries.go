// Code generated by "esc -o queries.go -pkg postgres -private ./queries.sql"; DO NOT EDIT.

package postgres

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sync"
	"time"
)

type _escLocalFS struct{}

var _escLocal _escLocalFS

type _escStaticFS struct{}

var _escStatic _escStaticFS

type _escDirectory struct {
	fs   http.FileSystem
	name string
}

type _escFile struct {
	compressed string
	size       int64
	modtime    int64
	local      string
	isDir      bool

	once sync.Once
	data []byte
	name string
}

func (_escLocalFS) Open(name string) (http.File, error) {
	f, present := _escData[path.Clean(name)]
	if !present {
		return nil, os.ErrNotExist
	}
	return os.Open(f.local)
}

func (_escStaticFS) prepare(name string) (*_escFile, error) {
	f, present := _escData[path.Clean(name)]
	if !present {
		return nil, os.ErrNotExist
	}
	var err error
	f.once.Do(func() {
		f.name = path.Base(name)
		if f.size == 0 {
			return
		}
		var gr *gzip.Reader
		b64 := base64.NewDecoder(base64.StdEncoding, bytes.NewBufferString(f.compressed))
		gr, err = gzip.NewReader(b64)
		if err != nil {
			return
		}
		f.data, err = ioutil.ReadAll(gr)
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (fs _escStaticFS) Open(name string) (http.File, error) {
	f, err := fs.prepare(name)
	if err != nil {
		return nil, err
	}
	return f.File()
}

func (dir _escDirectory) Open(name string) (http.File, error) {
	return dir.fs.Open(dir.name + name)
}

func (f *_escFile) File() (http.File, error) {
	type httpFile struct {
		*bytes.Reader
		*_escFile
	}
	return &httpFile{
		Reader:   bytes.NewReader(f.data),
		_escFile: f,
	}, nil
}

func (f *_escFile) Close() error {
	return nil
}

func (f *_escFile) Readdir(count int) ([]os.FileInfo, error) {
	if !f.isDir {
		return nil, fmt.Errorf(" escFile.Readdir: '%s' is not directory", f.name)
	}

	fis, ok := _escDirs[f.local]
	if !ok {
		return nil, fmt.Errorf(" escFile.Readdir: '%s' is directory, but we have no info about content of this dir, local=%s", f.name, f.local)
	}
	limit := count
	if count <= 0 || limit > len(fis) {
		limit = len(fis)
	}

	if len(fis) == 0 && count > 0 {
		return nil, io.EOF
	}

	return fis[0:limit], nil
}

func (f *_escFile) Stat() (os.FileInfo, error) {
	return f, nil
}

func (f *_escFile) Name() string {
	return f.name
}

func (f *_escFile) Size() int64 {
	return f.size
}

func (f *_escFile) Mode() os.FileMode {
	return 0
}

func (f *_escFile) ModTime() time.Time {
	return time.Unix(f.modtime, 0)
}

func (f *_escFile) IsDir() bool {
	return f.isDir
}

func (f *_escFile) Sys() interface{} {
	return f
}

// _escFS returns a http.Filesystem for the embedded assets. If useLocal is true,
// the filesystem's contents are instead used.
func _escFS(useLocal bool) http.FileSystem {
	if useLocal {
		return _escLocal
	}
	return _escStatic
}

// _escDir returns a http.Filesystem for the embedded assets on a given prefix dir.
// If useLocal is true, the filesystem's contents are instead used.
func _escDir(useLocal bool, name string) http.FileSystem {
	if useLocal {
		return _escDirectory{fs: _escLocal, name: name}
	}
	return _escDirectory{fs: _escStatic, name: name}
}

// _escFSByte returns the named file from the embedded assets. If useLocal is
// true, the filesystem's contents are instead used.
func _escFSByte(useLocal bool, name string) ([]byte, error) {
	if useLocal {
		f, err := _escLocal.Open(name)
		if err != nil {
			return nil, err
		}
		b, err := ioutil.ReadAll(f)
		_ = f.Close()
		return b, err
	}
	f, err := _escStatic.prepare(name)
	if err != nil {
		return nil, err
	}
	return f.data, nil
}

// _escFSMustByte is the same as _escFSByte, but panics if name is not present.
func _escFSMustByte(useLocal bool, name string) []byte {
	b, err := _escFSByte(useLocal, name)
	if err != nil {
		panic(err)
	}
	return b
}

// _escFSString is the string version of _escFSByte.
func _escFSString(useLocal bool, name string) (string, error) {
	b, err := _escFSByte(useLocal, name)
	return string(b), err
}

// _escFSMustString is the string version of _escFSMustByte.
func _escFSMustString(useLocal bool, name string) string {
	return string(_escFSMustByte(useLocal, name))
}

var _escData = map[string]*_escFile{

	"/queries.sql": {
		name:    "queries.sql",
		local:   "./queries.sql",
		size:    7801,
		modtime: 1600268060,
		compressed: `
H4sIAAAAAAAC/+yY32+jRhDHn71/xQhRHT7tpYfT31ceiL1W0WFIYX137gvizLaH6mAXcJpI/uOrXRxY
DMTp+cF+4CUSO9/ZGeb7yQTlzRtIwjv2CyxTFuYs2GYszYI8/LxiaOwRkxKg5o1NwJqC41Ignyyf+iBk
oKFBHAElnyjcetbM9BbwniwwGhSXRUGYA7VmxKfm7Jb+IS5w5raN0WC7iY4owmUe37doMBqwuzBeFXXl
K5N7lsZ/xiwKKgFGg02YZf+u0yj4EmZf4GZBiSmnFUnLMI/XSZCv/2aJJDyMJ+whb/ZTk7CHTZyyrKlK
2XJ9z9LHtiJlrL1AGe68fOw6PvVMy6EgXj7YJvE/WwZzx/p9TjRxNkTDdwih0vKMrdgyD7I8zDPkE5uM
KYzduUO110MwfcjXebiCqefOCr/fSblxkrE0F7ggy/GJR8FyqLsH44Npz4kPmqpjUEcY1GsM6ncY1O8x
qD9gUH/EoP6EQf0Zg6q/5T+4UudS/XooFypAEYWCz49BHKH57YRjWVTyCQWJJQNUHaMaOoboABVIGLwV
1CDF4N2hOigG7xZ10WHw90CtbBj89VAXEwZ/cdTGgsHHgRokGGJCqA0BHtLh42/EIxBH4nEkzy5iK1af
3YTYhBLJ03p2S3KciGnuN0PnBQcj579bYDoT6BrDr+C4H7Wa03scpW73TMYRBlStFIwqw+te48LlpsEH
3nbbavqgyLErfqp0GN0Q7wNKt/uNlCqmtFPBM57On7ppMFITVV20MVOTStVRFxNgWzOLgv6MVWLGvVtn
datcZMcMy0rHgohly6CyqnJQ1OXiqzhSanZWkepMkT2uBNWZcrCSS4l8qux5qKLiUWlZ11WJg4hyuMRL
Ze1YeR4pkfC/uGpmvAyuZt6LCBNpL8KsrjzOWl0vAzcmlq2VXwfuB+JpQ/gWNHUEr0G/ejsUnwyrMMuD
TfgX6wLUtt4TePXNK9jtOKq7nXhwvQnx4GYBEmgT4o/3KKsjcKdT/qdevT5OddhD3UN9oVCbX8m02NQV
ez3UPdRnhlri6KRN3UPdQ32JUJ+0qWWweqx7rM+MdQ2Tk7Z1D3YP9qWCfdLGPvgXVk90T/RZiC5EJ+3o
HuUe5ctBuWsr/xcAAP//xepKxXkeAAA=
`,
	},
}

var _escDirs = map[string][]os.FileInfo{}
