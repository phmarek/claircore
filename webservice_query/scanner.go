// Package webservice_query implements a package indexer that pushes hash-values to a webservice
// vim: set ts=4 sw=4 et : 
package webservice_query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/baggage"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/java"
)

const (
	name    = "webservice_query"
	kind    = "package"
	version = "1.0"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

type ScannerConfig struct {
	URL                       string  `yaml:"url" json:"url"`
	LogUnknowns               bool    `yaml:"log_unknowns" json:"log_unknowns"`
	ReportUnknownFilesPackage bool    `yaml:"report_unknowns_package" json:"report_unknowns_package"`
}


type QueryResult struct {
	Dataset string `json:"timestamp"`
	// CpuTime math.Float64 `json:"cpu-secs"`
	Warnings []string `json:"warnings"`
	Unknowns map[string][]string `json:"unknown"`
	Packages []*claircore.Package `json:"pkgs"`
}

// Scanner implements the scanner.PackageScanner interface.
type Scanner struct{
	client 		              *http.Client
	URL 		              string
	logUnknowns               bool
	reportUnknownFilesPackage bool
}

// Name implements scanner.VersionedScanner.
func (ps *Scanner) Name() string { return name }

// Version implements scanner.VersionedScanner.
func (ps *Scanner) Version() string { return version }

// Kind implements scanner.VersionedScanner.
func (ps *Scanner) Kind() string { return kind }

var cfg ScannerConfig


func (s *Scanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "webservice_query/Scanner.Configure",
		"version", s.Version())
	if err := f(&cfg); err != nil {
		return err
	}
	s.client = c
	s.URL = cfg.URL
	s.reportUnknownFilesPackage = cfg.ReportUnknownFilesPackage
	s.logUnknowns = cfg.LogUnknowns
	zlog.Debug(ctx).
		Str("url", s.URL).
		Bool("logUnknowns", s.logUnknowns).
		Bool("reportUnknownFilesPackage", s.reportUnknownFilesPackage).
		Msg("configured")
	return nil
}

func recursiveJarRunner(ctx context.Context, sys fs.FS,
							path string, pre string, 
							depth int, maxDepth *int,
							output strings.Builder) error {
	prefix  := fmt.Sprintf("%s%s:", pre, path)

	ctx = zlog.ContextWithValues(ctx,
		"jarPrefix", prefix,
		"depth", fmt.Sprintf("%d", depth))

	if depth > *maxDepth {
		*maxDepth = depth
	}

	buf := java.GetBuf()
	defer java.PutBuf(buf)

	f, err := sys.Open(path)
	if err != nil {
		zlog.Warn(ctx).Err(err).
		Str("file", pre).
		Msg("Error reading file")
		return err
	}
	defer f.Close()

	h := sha256.New()

	zipfile, err := java.OpenAJarFile(ctx, *buf, f, h)
	if err != nil {
		zlog.Error(ctx).Err(err).
		Msg("Error reading jar")
		return err
	}

	for _, f := range zipfile.File {
		if (f.FileInfo().IsDir()) {
			continue
		}

		if strings.HasSuffix(strings.ToLower(f.Name), ".jar") {
			recursiveJarRunner(ctx, sys, prefix, f.Name, depth +1, maxDepth, output)
		}

		rc, err := f.Open()
		if err != nil {
			zlog.Warn(ctx).Err(err).
			Str("file", f.Name).
			Msg("Error opening jar-content")
			return err
		}
		h.Reset()
		if _, err := io.Copy(h, rc); err != nil {
			zlog.Warn(ctx).Err(err).
			Str("file", f.Name).
			Msg("Error reading jar-content")
			return err
		}

		output.WriteString(hex.EncodeToString(h.Sum(nil)))
		output.WriteString(" /")
		output.WriteString(prefix)
		output.WriteString(f.Name)
		output.WriteString("\x00")

		rc.Close()
	}

	return nil
}


// Scan hashes all files within the layer and pushes the SHA256 and the filenames
// to the configured webservice.
//
// The POST data is formatted as
//   <nul>
//   sha256-in-hex<space>filename<nul>
// with contents within a jar-file being described as "<jar-file>:<path-in-zip>".
//
// The strings "${LAYER}" and "${ID}" in the URL (without quotes)
// are replaced by the layer checksum and the request ID, for remote logging.
//
//
// Because UNIX pathnames are defined as byte sequences,
// we post binary data and use the NUL character as separator.
// 
// The web service accepts a few different formats, also a cli call
//   $ find ... -exec sha256sum {} + | curl ...
// so to unambigously define the NUL separator character we send it as first byte.
// (Any filename could have <CR>, <NL>, etc. in it.)
//
func DoScan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if (cfg.URL == "") {
		zlog.Error(ctx).Msg("No URL configured, cannot run")
		return nil, nil
	}

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("webservice_query: opening layer failed: %w", err)
	}

	var post_content strings.Builder
	post_content.Grow(4 * 1024 * 1024)
	/* Start with a NUL, to define the line terminator being used */
	post_content.WriteString("\x00")

	h := sha256.New()
	found := 0
	jars := 0
	maxDepth := 0

	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Type().IsRegular() {
			found++

			// TODO: file type detection (but not all zip files?)
			// Break down other file types?
			if strings.HasSuffix(strings.ToLower(p), ".jar") {
				jars++
				recursiveJarRunner(ctx, sys, p, "", 1, &maxDepth, post_content)
			}

			f, err := sys.Open(p)
			if err != nil {
				zlog.Warn(ctx).Err(err).
				Str("file", p).
				Msg("Error reading file")
			}
			defer f.Close()

			h.Reset()
			if _, err := io.Copy(h, f); err != nil {
					zlog.Warn(ctx).Err(err)
			}

			post_content.WriteString(hex.EncodeToString(h.Sum(nil)))
			post_content.WriteString(" /")
			post_content.WriteString(p)
			post_content.WriteString("\x00")
		}
		return nil
	}

	if err := fs.WalkDir(sys, ".", walk); err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Int("maxDepth", maxDepth).
		Int("jars", jars).
		Int("fcount", found).
		Msg("scan statistics")

	if (found == 0) {
		return nil, nil
	}

	post_data := post_content.String()
	q_url1 := strings.Replace(cfg.URL, "${LAYER}", url.QueryEscape(layer.Hash.String()), -1)

	bag := baggage.FromContext(ctx)
	r_id := bag.Member("request_id")
	q_url2 := strings.Replace(q_url1, "${ID}", url.QueryEscape(r_id.Value()), -1)

	resp, err := http.Post(q_url2, "application/binary", strings.NewReader(post_data)) 
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("Error POSTing to webservice")
		return nil, err
	}

	var result QueryResult

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&result)
	if err != nil { 
		zlog.Warn(ctx).Err(err).Msg("Can't read HTTP data")
		return nil, err
	}

	zlog.Debug(ctx).
		Str("version", result.Dataset).
		Msg("webservice query succeeded")

	m_d := claircore.Package{
		Name: "jar-max-depth",
		Version: fmt.Sprintf("%d", maxDepth),
	}
	result.Packages = append(result.Packages, &m_d)

	/* Too much noise?? */
	if (len(result.Unknowns) > 0) {
		if (cfg.ReportUnknownFilesPackage) {
			u_p := claircore.Package{
				Name: "unknown-hashes",
				Version: fmt.Sprintf("%d", len(result.Unknowns)),
			}
			result.Packages = append(result.Packages, &u_p)
		}
		if (cfg.LogUnknowns) {
			data := zerolog.Arr()
			for h, _ := range result.Unknowns {
				data.Str(h)
			}
			zlog.Warn(ctx).
			Array("unknowns", data).
			Msg("Unknown hash values encountered")
		}
	}

	if (len(result.Warnings) > 0) {
		data := zerolog.Arr()
		for _, s := range result.Warnings {
			data.Str(s)
		}
		zlog.Warn(ctx).
			Array("warnings", data).
			Msg("Warnings found")
	}

	zlog.Debug(ctx).
		Int("count", len(result.Packages)).
		Msg("found packages")

	return result.Packages, nil
}


// It's expected to return (nil, nil) if there's no webservice configured.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	// Preamble
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "webservice_query/Scanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")

	pkgs, err := DoScan(ctx, layer)
	return pkgs, err
}


func MergePackages(ctx context.Context, layer *claircore.Layer, pkgs []*claircore.Package) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "webservice_query/Scanner.MergePackages",
		"version", version,
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")

	/* TODO: use a cache, indexed by layer */
	new_pkgs, err := DoScan(ctx, layer)
	if err != nil {
		return nil, err
	}

	merged := pkgs
	outer:
	for _,n_pkg := range(new_pkgs) {
		for _,o_pkg := range(pkgs) {
			if n_pkg.Name == o_pkg.Name && n_pkg.Version == o_pkg.Version {
				continue outer
			}
		}

		/* Not found, append */
		merged = append(merged, n_pkg)
	}

	return merged, nil
}
