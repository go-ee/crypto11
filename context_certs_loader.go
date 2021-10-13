package crypto11

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func (c *Context) loadCertPools() (err error) {
	if c.cfg.IgnoreSystemCertPool {
		c.roots = x509.NewCertPool()
	} else {
		if c.roots, err = x509.SystemCertPool(); err != nil {
			return
		}
	}
	c.inters = x509.NewCertPool()

	if c.cfg.CertFiles != "" {
		for _, file := range strings.Split(c.cfg.CertFiles, ",") {
			err = c.importCertFromFile(file)
		}
	}

	if c.cfg.CertDirectories != "" {
		for _, directory := range strings.Split(c.cfg.CertDirectories, ",") {
			err = c.importCertsFromDirectory(directory)
		}
	}
	return
}

func (c *Context) importCertsFromDirectory(directory string) (err error) {
	var files []fs.FileInfo
	if files, err = ioutil.ReadDir(directory); err != nil {
		return
	}

	for _, file := range files {
		_ = c.importCertFromFile(filepath.Join(directory, file.Name()))
	}
	return
}

func (c *Context) importCertFromFile(file string) (err error) {
	var data []byte
	if data, err = os.ReadFile(file); err != nil {
		return
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(certBytes); err != nil {
			continue
		}

		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			c.roots.AddCert(cert)
		} else {
			c.inters.AddCert(cert)
		}
	}
	return
}
