package oracle

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

const (
	allDB = `https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2`
	//doc:url updater
	baseURL = `https://linux.oracle.com/security/oval/com.oracle.elsa-%d.xml.bz2`
)

// Updater implements driver.Updater for Oracle Linux.
type Updater struct {
	year             int
	ovalutil.Fetcher // Fetch method promoted via embed
}

// Option configures the provided Updater.
type Option func(*Updater) error

// NewUpdater returns an updater configured according to the provided Options.
//
// If year is -1, the "all" database will be pulled.
func NewUpdater(year int, opts ...Option) (*Updater, error) {
	uri := allDB
	if year != -1 {
		uri = fmt.Sprintf(baseURL, year)
	}
	u := Updater{
		year: year,
	}
	var err error
	u.Fetcher.URL, err = url.Parse(uri)
	if err != nil {
		return nil, err
	}
	u.Fetcher.Compression = ovalutil.CompressionBzip2
	for _, o := range opts {
		if err := o(&u); err != nil {
			return nil, err
		}
	}

	return &u, nil
}

// WithURL overrides the default URL to fetch an OVAL database.
func WithURL(uri, compression string) Option {
	c, cerr := ovalutil.ParseCompressor(compression)
	u, uerr := url.Parse(uri)
	return func(up *Updater) error {
		// Return any errors from the outer function.
		switch {
		case cerr != nil:
			return cerr
		case uerr != nil:
			return uerr
		}
		up.Fetcher.Compression = c
		up.Fetcher.URL = u
		return nil
	}
}

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Name satifies the driver.Updater interface.
func (u *Updater) Name() string {
	which := `all`
	if u.year != -1 {
		which = strconv.Itoa(u.year)
	}
	return fmt.Sprintf("oracle-%s-updater", which)
}
