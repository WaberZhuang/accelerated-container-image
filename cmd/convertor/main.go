/*
   Copyright The Accelerated Container Image Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/containerd/accelerated-container-image/cmd/convertor/builder"
	"github.com/containerd/accelerated-container-image/cmd/convertor/database"
	"github.com/containerd/accelerated-container-image/pkg/convertor/turbooci"
	dockerspec "github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/log"
	_ "github.com/go-sql-driver/mysql"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	orasremote "oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"

	"github.com/spf13/cobra"
)

var (
	repo             string
	user             string
	plain            bool
	tagInput         string
	tagOutput        string
	dir              string
	oci              bool
	mkfs             bool
	verbose          bool
	vsize            int
	fastoci          string
	turboOCI         string
	turboOCIReferrer bool
	overlaybd        string
	dbstr            string
	dbType           string
	platformStr      []string

	// certification
	certDirs    []string
	rootCAs     []string
	clientCerts []string
	insecure    bool
	// debug
	reserve      bool
	noUpload     bool
	dumpManifest bool

	rootCmd = &cobra.Command{
		Use:   "convertor",
		Short: "An image conversion tool from oci image to overlaybd image.",
		Long:  "overlaybd convertor is a standalone userspace image conversion tool that helps converting oci images to overlaybd images",
		Run: func(cmd *cobra.Command, args []string) {
			if verbose {
				logrus.SetLevel(logrus.DebugLevel)
			}
			tb := ""
			if overlaybd == "" && fastoci == "" && turboOCI == "" && !turboOCIReferrer {
				if tagOutput == "" {
					logrus.Error("output-tag is required, you can specify it by [-o|--overlaybd|--turboOCI]")
					os.Exit(1)
				}
				overlaybd = tagOutput
			}
			if fastoci != "" {
				tb = fastoci
			}
			if turboOCI != "" {
				tb = turboOCI
			}

			ctx := context.Background()
			opt := builder.BuilderOptions{
				Ref:       repo + ":" + tagInput,
				Auth:      user,
				PlainHTTP: plain,
				WorkDir:   dir,
				OCI:       oci,
				Mkfs:      mkfs,
				Vsize:     vsize,
				CertOption: builder.CertOption{
					CertDirs:    certDirs,
					RootCAs:     rootCAs,
					ClientCerts: clientCerts,
					Insecure:    insecure,
				},
				Reserve:      reserve,
				NoUpload:     noUpload,
				DumpManifest: dumpManifest,
			}
			if overlaybd != "" {
				logrus.Info("building [Overlaybd - Native]  image...")
				opt.Engine = builder.Overlaybd
				opt.TargetRef = repo + ":" + overlaybd

				switch dbType {
				case "mysql":
					if dbstr == "" {
						logrus.Warnf("no db-str was provided, falling back to no deduplication")
					}
					db, err := sql.Open("mysql", dbstr)
					if err != nil {
						logrus.Errorf("failed to open the provided mysql db: %v", err)
						os.Exit(1)
					}
					opt.DB = database.NewSqlDB(db)
				case "":
				default:
					logrus.Warnf("db-type %s was provided but is not one of known db types. Available: mysql", dbType)
					logrus.Warnf("falling back to no deduplication")
				}

				builder, err := builder.NewOverlayBDBuilder(ctx, opt)
				if err != nil {
					logrus.Errorf("failed to create overlaybd builder: %v", err)
					os.Exit(1)
				}
				if err := builder.Build(ctx); err != nil {
					logrus.Errorf("failed to build overlaybd: %v", err)
					os.Exit(1)
				}
				logrus.Info("overlaybd build finished")
			}
			if tb != "" || turboOCIReferrer {
				turboOCI = tb
				if err := buildTurboOCI(ctx); err != nil {
					log.G(ctx).Fatalf("failed to build TurboOCIv1: %s", err)
				}
				logrus.Info("TurboOCIv1 build finished")
			}
		},
	}
)

func init() {
	rootCmd.Flags().SortFlags = false
	rootCmd.Flags().StringVarP(&repo, "repository", "r", "", "repository for converting image (required)")
	rootCmd.Flags().StringVarP(&user, "username", "u", "", "user[:password] Registry user and password")
	rootCmd.Flags().BoolVarP(&plain, "plain", "", false, "connections using plain HTTP")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "", false, "show debug log")
	rootCmd.Flags().StringVarP(&tagInput, "input-tag", "i", "", "tag for image converting from (required)")
	rootCmd.Flags().StringVarP(&tagOutput, "output-tag", "o", "", "tag for image converting to")
	rootCmd.Flags().StringVarP(&dir, "dir", "d", "tmp_conv", "directory used for temporary data")
	rootCmd.Flags().BoolVarP(&oci, "oci", "", false, "export image with oci spec")
	rootCmd.Flags().BoolVarP(&mkfs, "mkfs", "", true, "make ext4 fs in bottom layer")
	rootCmd.Flags().IntVarP(&vsize, "vsize", "", 64, "virtual block device size (GB)")
	rootCmd.Flags().StringVar(&fastoci, "fastoci", "", "build 'Overlaybd-Turbo OCIv1' format (old name of turboOCIv1. deprecated)")
	rootCmd.Flags().StringVar(&turboOCI, "turboOCI", "", "build 'Overlaybd-Turbo OCIv1' format, as a tag")
	rootCmd.Flags().BoolVar(&turboOCIReferrer, "turboOCI-referrer", false, "build 'Overlaybd-Turbo OCIv1' format, as a referrer")
	rootCmd.Flags().StringVar(&overlaybd, "overlaybd", "", "build overlaybd format")
	rootCmd.Flags().StringVar(&dbstr, "db-str", "", "db str for overlaybd conversion")
	rootCmd.Flags().StringVar(&dbType, "db-type", "", "type of db to use for conversion deduplication. Available: mysql. Default none")
	rootCmd.Flags().StringSliceVar(&platformStr, "platform", []string{}, "if set, convert only manifest with matched platform (support TurboOCI only)")

	// certification
	rootCmd.Flags().StringArrayVar(&certDirs, "cert-dir", nil, "In these directories, root CA should be named as *.crt and client cert should be named as *.cert, *.key")
	rootCmd.Flags().StringArrayVar(&rootCAs, "root-ca", nil, "root CA certificates")
	rootCmd.Flags().StringArrayVar(&clientCerts, "client-cert", nil, "client cert certificates, should form in ${cert-file}:${key-file}")
	rootCmd.Flags().BoolVarP(&insecure, "insecure", "", false, "don't verify the server's certificate chain and host name")

	// debug
	rootCmd.Flags().BoolVar(&reserve, "reserve", false, "reserve tmp data")
	rootCmd.Flags().BoolVar(&noUpload, "no-upload", false, "don't upload layer and manifest")
	rootCmd.Flags().BoolVar(&dumpManifest, "dump-manifest", false, "dump manifest")

	rootCmd.MarkFlagRequired("repository")
	rootCmd.MarkFlagRequired("input-tag")
}

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		<-sigChan
		os.Exit(0)
	}()

	rootCmd.Execute()
}

func buildTurboOCI(ctx context.Context) error {
	if !reserve {
		defer os.RemoveAll(dir)
	}
	tls, err := loadTLSConfig(CertOption{
		CertDirs:    certDirs,
		RootCAs:     rootCAs,
		ClientCerts: clientCerts,
		Insecure:    insecure,
	})
	if err != nil {
		return fmt.Errorf("failed to load tls config: %w", err)
	}
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:       30 * time.Second,
			KeepAlive:     30 * time.Second,
			FallbackDelay: 300 * time.Millisecond,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		TLSClientConfig:       tls,
		ExpectContinueTimeout: 5 * time.Second,
	}
	client := &orasauth.Client{
		Client: &http.Client{
			Transport: orasretry.NewTransport(transport),
		},
		Header: http.Header{
			"User-Agent": {"overlaybd-convertor"},
		},
		Cache: orasauth.DefaultCache,
		Credential: func(ctx context.Context, s string) (orasauth.Credential, error) {
			pos := strings.Index(user, ":")
			if pos < 0 {
				return orasauth.Credential{}, nil
			}
			return orasauth.Credential{
				Username: user[:pos],
				Password: user[pos+1:],
			}, nil
		},
	}
	reference := repo + ":" + tagInput

	store, err := orasremote.NewRepository(reference)
	if err != nil {
		return fmt.Errorf("failed to new oras repository: %w", err)
	}
	store.Client = client

	var platformFilters []platforms.Matcher
	for _, pstr := range platformStr {
		p, err := platforms.Parse(pstr)
		if err != nil {
			return fmt.Errorf("failed to parse platform %s: %w", pstr, err)
		}
		platformFilters = append(platformFilters, platforms.NewMatcher(p))
	}

	src, err := store.Resolve(ctx, reference)
	if err != nil {
		return fmt.Errorf("failed to resolve: %w", err)
	}
	var manifestDescs []ocispec.Descriptor
	switch src.MediaType {
	case ocispec.MediaTypeImageManifest, dockerspec.MediaTypeDockerSchema2Manifest:
		manifestDescs = append(manifestDescs, src)
	case ocispec.MediaTypeImageIndex, dockerspec.MediaTypeDockerSchema2ManifestList:
		rc, err := store.Fetch(ctx, src)
		if err != nil {
			return fmt.Errorf("failed to fetch index: %w", err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			return fmt.Errorf("failed to read index: %w", err)
		}
		var index ocispec.Index
		if err := json.Unmarshal(b, &index); err != nil {
			return fmt.Errorf("failed to unmarshal index: %w", err)
		}
		for _, m := range index.Manifests {
			if len(platformFilters) == 0 {
				manifestDescs = append(manifestDescs, m)
			} else {
				for _, f := range platformFilters {
					if f.Match(*m.Platform) {
						manifestDescs = append(manifestDescs, m)
						break
					}
				}
			}
		}
	}
	if len(manifestDescs) == 0 {
		log.G(ctx).Warn("no matched manifest, do nothing")
		return nil
	}

	var mu sync.Mutex
	var turboDescs []ocispec.Descriptor
	g, gctx := errgroup.WithContext(ctx)
	for _, _mDesc := range manifestDescs {
		mDesc := _mDesc
		g.Go(func() error {
			var platform string
			var rctx context.Context
			if mDesc.Platform == nil {
				platform = ""
				rctx = gctx
			} else {
				platform = platforms.Format(*mDesc.Platform)
				rctx = log.WithLogger(gctx, log.G(ctx).WithField("platform", platform))
			}
			workdir := filepath.Join(dir, strings.ReplaceAll(platform, "/", "-"))

			log.G(rctx).WithFields(log.Fields{
				"manifest digest": mDesc.Digest,
				"work dir":        workdir,
			}).Info("building [Overlaybd - Turbo OCIv1] ...")

			desc, err := turbooci.Convert(rctx, mDesc, store,
				turbooci.WithWorkdir(workdir),
				turbooci.WithOCIFormat(oci),
				turbooci.WithManifestFormat(turboOCI != ""),
				turbooci.WithReferrerFormat(turboOCIReferrer),
				turbooci.WithVirtualSize(vsize),
			)
			if err != nil {
				return fmt.Errorf("(platform %s) failed to build: %w", platform, err)
			}
			desc.Platform = mDesc.Platform

			mu.Lock()
			defer mu.Unlock()
			turboDescs = append(turboDescs, desc)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if turboOCI != "" {
		if len(turboDescs) == 1 {
			if err := store.Tag(ctx, turboDescs[0], turboOCI); err != nil {
				return fmt.Errorf("failed to tag TurboOCIv1: %w", err)
			}
		} else {
			index := ocispec.Index{}
			index.SchemaVersion = 2
			if turboDescs[0].MediaType == ocispec.MediaTypeImageManifest {
				index.MediaType = ocispec.MediaTypeImageIndex
			} else {
				index.MediaType = dockerspec.MediaTypeDockerSchema2ManifestList
			}
			index.Manifests = turboDescs
			b, err := json.Marshal(index)
			if err != nil {
				return fmt.Errorf("failed to marshal TurboOCI index: %w", err)
			}
			expected := ocispec.Descriptor{
				Digest:    digest.FromBytes(b),
				Size:      int64(len(b)),
				MediaType: index.MediaType,
			}
			log.G(ctx).Debug(string(b))
			if err := store.PushReference(ctx, expected, bytes.NewReader(b), turboOCI); err != nil {
				return fmt.Errorf("failed to tag TurboOCIv1 (index format): %w", err)
			}
		}
	}

	return nil
}

// -------------------- certification --------------------
type CertOption struct {
	CertDirs    []string
	RootCAs     []string
	ClientCerts []string
	Insecure    bool
}

func loadTLSConfig(opt CertOption) (*tls.Config, error) {
	type clientCertPair struct {
		certFile string
		keyFile  string
	}
	var clientCertPairs []clientCertPair
	// client certs from option `--client-cert`
	for _, cert := range opt.ClientCerts {
		s := strings.Split(cert, ":")
		if len(s) != 2 {
			return nil, fmt.Errorf("client cert %s: invalid format", cert)
		}
		clientCertPairs = append(clientCertPairs, clientCertPair{
			certFile: s[0],
			keyFile:  s[1],
		})
	}
	// root CAs / client certs from option `--cert-dir`
	for _, d := range opt.CertDirs {
		fs, err := os.ReadDir(d)
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("failed to read cert directory %q: %w", d, err)
		}
		for _, f := range fs {
			if strings.HasSuffix(f.Name(), ".crt") {
				opt.RootCAs = append(opt.RootCAs, filepath.Join(d, f.Name()))
			}
			if strings.HasSuffix(f.Name(), ".cert") {
				clientCertPairs = append(clientCertPairs, clientCertPair{
					certFile: filepath.Join(d, f.Name()),
					keyFile:  filepath.Join(d, strings.TrimSuffix(f.Name(), ".cert")+".key"),
				})
			}
		}
	}
	tlsConfig := &tls.Config{}
	// root CAs from ENV ${SSL_CERT_FILE} and ${SSL_CERT_DIR}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		if runtime.GOOS == "windows" {
			systemPool = x509.NewCertPool()
		} else {
			return nil, fmt.Errorf("failed to get system cert pool: %w", err)
		}
	}
	tlsConfig.RootCAs = systemPool
	// root CAs from option `--root-ca`
	for _, file := range opt.RootCAs {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA file %q: %w", file, err)
		}
		tlsConfig.RootCAs.AppendCertsFromPEM(b)
	}
	// load client certs
	for _, c := range clientCertPairs {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert pair {%q, %q}: %w", c.certFile, c.keyFile, err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	tlsConfig.InsecureSkipVerify = opt.Insecure
	return tlsConfig, nil
}
