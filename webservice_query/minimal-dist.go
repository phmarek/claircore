package webservice_query

import (
	"context"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

type DistributionScanner struct{}

func (*DistributionScanner) Name() string { return "minimal" }

func (*DistributionScanner) Version() string { return "0" }

func (*DistributionScanner) Kind() string { return "distribution" }

func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	/* Can we give this a lower detection priority?
	 * How would a mixed Debian/RedHat Image be shown? */
	d := claircore.Distribution{
		PrettyName:      "Minimal Filesystem",
		Name:            "Minimal Filesystem",
		VersionID:       "0",
		Version:         "0",
		VersionCodeName: "minimal",
		DID:             "minimal",
	}
	return []*claircore.Distribution{&d}, nil
}
