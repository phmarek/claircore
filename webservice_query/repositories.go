package webservice_query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/trace"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/rhel/dockerfile"
	"github.com/quay/claircore/rhel/internal/common"
	"github.com/quay/claircore/rhel/internal/containerapi"
	"github.com/quay/claircore/toolkit/types/cpe"
)

type RepositoryScanner struct {
}

var (
	_ indexer.RepositoryScanner = (*RepositoryScanner)(nil)
	_ indexer.RPCScanner        = (*RepositoryScanner)(nil)
	_ indexer.VersionedScanner  = (*RepositoryScanner)(nil)
)


// Name implements [indexer.VersionedScanner].
func (*RepositoryScanner) Name() string { return "webservice-repo-lister" }

// Version implements [indexer.VersionedScanner].
func (*RepositoryScanner) Version() string { return "1.0" }

// Kind implements [indexer.VersionedScanner].
func (*RepositoryScanner) Kind() string { return "repository" }

// Scan implements [indexer.RepositoryScanner].
func (r *RepositoryScanner) Scan(ctx context.Context, l *claircore.Layer) (repositories []*claircore.Repository, err error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "webservice_query/RepositoryScanner.Scan",
		"version", r.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	pkgs, err := DoScan(ctx, l)
	_ = pkgs
	if err != nil { 
		zlog.Warn(ctx).Err(err).Msg("Error getting repo data")
		return nil, err
	}
	return l.ViaChkSumIdentifiedRepos, nil
}
