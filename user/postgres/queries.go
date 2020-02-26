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
		size:    5836,
		modtime: 1582740901,
		compressed: `
H4sIAAAAAAAC/+yXXW+bPBTHr+NPcS78qKnkPhrt3jcuaOJoqAQ6cNZmN4gGT7WWkg5I10r58JMN5SXA
Ki3SlkrcRML+nxef3zkEHx1BFNzw97CIeZByf53wOPHT4GrJ0cilBqPAjFOLgjkB22FAL02PeaBkMEQD
EQKjlwzOXXNquHM4o3OCBpmz0A9SYOaUesyYnrOvyoE9syyCBuvb8AlFsEjFXYuGoAG/CcQyi1t1Gd3x
WHwTPPRLAUGD2yBJfq7i0L8Okms4nTNqVM0yo0WQilXkp6vvPKoIt/cjfp8286lJ+P2tiHnSVMV8sbrj
8UNbkGKvPUCx3el85Ngecw3TZqAO768j8WPNYWabn2d0qNYO0eEHhAriIkp4nCriyLQ96jIwbebkbL8Y
1ox6MMQaAXxMAJ8QwC8J4FcE8GsC+A0B/JYAfkcAay/kj1RqUqqd1AJlrFUg/+rBFyGanY9lZ2WRPMqg
0g46YI2gGn1dZYAyqrpMBTVg6zI7VGety2xRF2BdngO14tXl8VAXVl0eHLXh1GU5UAOmriqE2ijKLQ0u
PlGXggjV43G1diFf8nrtxtSijMLEdaZ5AWvWLcYiUtXMh7vTwVbJ5XiAYY+hqwwfwXYuhjXSCV/yRVrN
1qMWHTEQIQFUvhUIKoHXWZOMchPwFtturIZXy/j/FvUjl21pvt5Nftug3GrvB8ODx+U8j0ZvVCVF/LZO
qQrLZdTVB2CZU5OB9hs8qq49ob9OqHhhPQUpKSj5IU8Wfomnp/aPqFnmGYWD/w5gs5H8Nhv14Lhj6sLp
HCofPmPqjXK++BicyUT+z+GTp1EHPennRdr4Q9BqpkuMPen9JF35Nt1ppnvSz4j0TjNdRdez3k/WtdvO
TnPd035mtHea7f7StMeYM9FO09zz3Xu+XfP7KwAA//8CY3NzzBYAAA==
`,
	},
}

var _escDirs = map[string][]os.FileInfo{}
