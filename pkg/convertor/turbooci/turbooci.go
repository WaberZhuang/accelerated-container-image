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

package turbooci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/containerd/accelerated-container-image/pkg/convertor/internal"
	"github.com/containerd/accelerated-container-image/pkg/label"
	"github.com/containerd/accelerated-container-image/pkg/snapshot"
	"github.com/containerd/accelerated-container-image/pkg/version"
	"github.com/containerd/containerd/archive/compression"
	dockerspec "github.com/containerd/containerd/images"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	orascontent "oras.land/oras-go/v2/content"
)

const ArtifactMediaType = "application/vnd.alibaba.overlaybd.turbo.v1+json"

// TODO
//  1. cached layer
//  2. streaming apply
//  3. chunked download

type ConvertOption func(opt *convertOption)

type convertOption struct {
	workdir        string
	manifestFormat bool
	referrerFormat bool
	metaFetcher    MetaFetcher
	ociFormat      bool
	vsize          int

	// (TODO) special fetcher, for chunked download
	downloader orascontent.Fetcher
}

func WithWorkdir(workdir string) ConvertOption {
	return func(opt *convertOption) {
		opt.workdir = workdir
	}
}

// If true, Convert will upload a traditional manifest (but won't tag it) without
// the 'subject' field, as registry may not support reference API
func WithManifestFormat(manifestFormat bool) ConvertOption {
	return func(opt *convertOption) {
		opt.manifestFormat = manifestFormat
	}
}

// If true, Convert will upload a referrer
func WithReferrerFormat(referrerFormat bool) ConvertOption {
	return func(opt *convertOption) {
		opt.referrerFormat = referrerFormat
	}
}

// If set, Convert will try to fetch meta instead of download whole layer
func WithMetaFetcher(metaFetcher MetaFetcher) ConvertOption {
	return func(opt *convertOption) {
		opt.metaFetcher = metaFetcher
	}
}

// If manifestFormat is set, all mediaTypes in the manifest will be forced to
// be in OCI format.
//
// This option has no effect on referrer, as it's always OCI.
func WithOCIFormat(ociFormat bool) ConvertOption {
	return func(opt *convertOption) {
		opt.ociFormat = ociFormat
	}
}

// Virtual block device size (GB), default is 64
func WithVirtualSize(vsize int) ConvertOption {
	return func(opt *convertOption) {
		opt.vsize = vsize
	}
}

// Convert return a descriptor of the TurboOCI index
//
// Note:
//  1. src must be a manifest, but not an index (manifest list)
//  2. If `manifestFormat` is set, Convert returns a descriptor of it, as the
//     caller may need it to tag or compose an index
func Convert(ctx context.Context, src ocispec.Descriptor, store orascontent.Storage, opts ...ConvertOption) (ocispec.Descriptor, error) {
	opt := &convertOption{}
	for _, o := range opts {
		o(opt)
	}
	if opt.workdir == "" {
		opt.workdir = "tmp_conv"
	}
	if opt.vsize == 0 {
		opt.vsize = 64
	}

	b := &convertor{
		src:           src,
		store:         store,
		convertOption: opt,
	}
	return b.convert(ctx)
}

type convertor struct {
	// required
	src   ocispec.Descriptor
	store orascontent.Storage

	// options
	*convertOption

	// private
	devConfig            *snapshot.OverlayBDBSConfig // overlaybd device config (lsmt config)
	manifest             ocispec.Manifest            // src manifest
	config               ocispec.Image               // src config
	manifestJSON         *gabs.Container             // manifest json, update and upload this
	configJSON           *gabs.Container             // config json, update and upload this
	chainIDs             []digest.Digest             // identity.ChainIDs(config.RootFS.DiffIDs)
	turboOCILayers       []ocispec.Descriptor        // TurboOCIv1 layers descriptors (compressed)
	turboOCIUncompressed []ocispec.Descriptor        // TurboOCIv1 layers descriptors (uncompressed)
	isGzipLayer          []bool                      // if the src layer is gzip
}

func (c *convertor) pathServiceConfig() string {
	return filepath.Join(c.workdir, "service.json")
}

func (c *convertor) pathCacheDir() string {
	return filepath.Join(c.workdir, "cache")
}

func (c *convertor) pathGzipCacheDir() string {
	return filepath.Join(c.workdir, "gzip_cache")
}

func (c *convertor) pathLayerDir(idx int) string {
	return filepath.Join(c.workdir, "layers", fmt.Sprintf("%d", idx))
}

func (c *convertor) pathLayerOCIv1(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "blob.OCIv1")
}

func (c *convertor) pathWritableData(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "writable.data")
}

func (c *convertor) pathWritableIndex(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "writable.index")
}

func (c *convertor) pathLayerDeviceConfig(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "config.v1.json")
}

func (c *convertor) pathLayerFSMeta(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "ext4.fs.meta")
}

func (c *convertor) pathLayerGzipIndex(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "gzip.meta")
}

func (c *convertor) pathLayerIdentity(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), ".turbo.ociv1")
}

func (c *convertor) pathLayerTurboOCI(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "TurboOCIv1.tar.gz")
}

// tar.meta consists of only the original layer's tar header
func (c *convertor) pathLayerTarMeta(idx int) string {
	return filepath.Join(c.pathLayerDir(idx), "tar.meta")
}

func (c *convertor) prepare(ctx context.Context) error {
	// prepare workdir
	if err := os.MkdirAll(c.workdir, 0755); err != nil {
		return fmt.Errorf("failed to create workdir: %w", err)
	}
	if err := os.Mkdir(c.pathCacheDir(), 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}
	if err := os.Mkdir(c.pathGzipCacheDir(), 0755); err != nil {
		return fmt.Errorf("failed to create gzip cache dir: %w", err)
	}
	svcConfig := fmt.Sprintf(`
	{
		"registryFsVersion": "v2",
		"logPath": "",
		"logLevel": 1,
		"cacheConfig": {
			"cacheType": "file",
			"cacheDir": "%s",
			"cacheSizeGB": 4
		},
		"gzipCacheConfig": {
			"enable": true,
			"cacheDir": "%s",
			"cacheSizeGB": 4
		},
		"credentialConfig": {
			"mode": "file",
			"path": ""
		},
		"ioEngine": 0,
		"download": {
			"enable": false
		},
		"p2pConfig": {
			"enable": false
		},
		"enableAudit": false
	}
	`, c.pathCacheDir(), c.pathGzipCacheDir())
	if err := os.WriteFile(c.pathServiceConfig(), []byte(svcConfig), 0644); err != nil {
		return fmt.Errorf("failed to write service config: %w", err)
	}

	// manifest & config
	fetch := func(ctx context.Context, desc ocispec.Descriptor, target any, targetJSON **gabs.Container) error {
		rc, err := c.store.Fetch(ctx, desc)
		if err != nil {
			return err
		}
		defer rc.Close()
		*targetJSON, err = internal.ParseJSON(rc, target)
		if err != nil {
			return err
		}
		return nil
	}
	if err := fetch(ctx, c.src, &c.manifest, &c.manifestJSON); err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	if err := fetch(ctx, c.manifest.Config, &c.config, &c.configJSON); err != nil {
		return fmt.Errorf("failed to fetch config: %w", err)
	}

	// init var
	c.chainIDs = identity.ChainIDs(c.config.RootFS.DiffIDs)
	c.turboOCILayers = make([]ocispec.Descriptor, len(c.manifest.Layers))
	c.turboOCIUncompressed = make([]ocispec.Descriptor, len(c.manifest.Layers))
	c.devConfig = &snapshot.OverlayBDBSConfig{}
	c.isGzipLayer = make([]bool, len(c.manifest.Layers))

	// check compression
	g, gctx := errgroup.WithContext(ctx)
	for _idx := range c.manifest.Layers {
		idx := _idx
		g.Go(func() error {
			rc, err := c.store.Fetch(gctx, c.manifest.Layers[idx])
			if err != nil {
				return fmt.Errorf("(layer-%d) failed to fetch: %w", idx, err)
			}
			defer rc.Close()
			drc, err := compression.DecompressStream(rc)
			if err != nil {
				return fmt.Errorf("(layer-%d) failed to new decompress stream: %w", idx, err)
			}
			algo := drc.GetCompression()
			switch algo {
			case compression.Gzip:
				c.isGzipLayer[idx] = true
			case compression.Uncompressed:
				c.isGzipLayer[idx] = false
			default:
				return fmt.Errorf("(layer-%d) unsupported compression algorithm: %s", idx, algo.Extension())
			}
			return nil
		})
	}

	return nil
}

func (c *convertor) convert(ctx context.Context) (ocispec.Descriptor, error) {
	start := time.Now()

	if err := c.prepare(ctx); err != nil {
		return ocispec.DescriptorEmptyJSON, err
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		downloaded := make([]chan struct{}, len(c.manifest.Layers))
		for _idx := range c.manifest.Layers {
			downloaded[_idx] = make(chan struct{})
			idx := _idx
			g.Go(func() error {
				if err := c.downloadLayer(gctx, idx); err != nil {
					return fmt.Errorf("failed to download layer-%d: %w", idx, err)
				}
				close(downloaded[idx])
				return nil
			})
		}
		for idx := range c.manifest.Layers {
			select {
			case <-gctx.Done():
				return gctx.Err()
			case <-downloaded[idx]:
			}
			if err := c.convertLayer(gctx, idx); err != nil {
				return fmt.Errorf("failed to convert layer-%d: %w", idx, err)
			}
			_idx := idx
			g.Go(func() error {
				if err := c.pushLayer(gctx, _idx); err != nil {
					return fmt.Errorf("failed to push layer-%d: %w", _idx, err)
				}
				return nil
			})
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		return ocispec.DescriptorEmptyJSON, err
	}

	// upload manifest / config / referrer
	c.prepareManifest()
	manifestDesc := ocispec.DescriptorEmptyJSON
	if c.manifestFormat {
		var err error
		manifestDesc, err = c.pushManifest(ctx)
		if err != nil {
			return ocispec.DescriptorEmptyJSON, err
		}
	}
	if c.referrerFormat {
		if err := c.pushReferrer(ctx); err != nil {
			return ocispec.DescriptorEmptyJSON, err
		}
	}

	log.G(ctx).Infof("convert done, elapsed: %.3f s", time.Since(start).Seconds())
	return manifestDesc, nil
}

// Once streaming apply is ready, deprecate this
func (c *convertor) downloadLayer(ctx context.Context, idx int) error {
	if err := os.MkdirAll(c.pathLayerDir(idx), 0755); err != nil {
		return fmt.Errorf("failed to create layer dir: %w", err)
	}
	var fetchFunc func(context.Context, ocispec.Descriptor) (io.ReadCloser, error)
	if c.downloader != nil {
		fetchFunc = c.downloader.Fetch
	} else {
		fetchFunc = c.store.Fetch
	}
	rc, err := fetchFunc(ctx, c.manifest.Layers[idx])
	if err != nil {
		return fmt.Errorf("failed to fetch: %w", err)
	}
	defer rc.Close()
	file, err := os.OpenFile(c.pathLayerOCIv1(idx), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()
	if _, err := io.Copy(file, rc); err != nil {
		return fmt.Errorf("failed to copy: %w", err)
	}
	return nil
}

func (c *convertor) convertLayer(ctx context.Context, idx int) error {
	start := time.Now()
	if err := c.cmdCreate(ctx, idx); err != nil {
		return fmt.Errorf("failed to cmd create: %w", err)
	}
	if err := c.cmdApplyMeta(ctx, idx); err != nil {
		return fmt.Errorf("failed to cmd apply: %w", err)
	}
	if err := c.cmdCommit(ctx, idx); err != nil {
		return fmt.Errorf("failed to cmd commit: %w", err)
	}
	file, err := os.Create(c.pathLayerIdentity(idx))
	if err != nil {
		return fmt.Errorf("failed to create identity file: %w", err)
	}
	file.Close()

	if c.turboOCILayers[idx], c.turboOCIUncompressed[idx], err = internal.BuildArchiveFromFiles(ctx,
		c.pathLayerTurboOCI(idx),
		compression.Gzip,
		c.pathLayerFSMeta(idx),
		c.pathLayerGzipIndex(idx),
		c.pathLayerIdentity(idx),
	); err != nil {
		return fmt.Errorf("failed to archive TurboOCIv1 Layer: %w", err)
	}

	log.G(ctx).WithFields(log.Fields{
		"digest": c.turboOCILayers[idx].Digest,
		"size":   c.turboOCILayers[idx].Size,
	}).Infof("convert layer-%d, elapsed: %.3f s", idx, time.Since(start).Seconds())
	return nil
}

func (c *convertor) pushLayer(ctx context.Context, idx int) error {
	start := time.Now()

	file, err := os.Open(c.pathLayerTurboOCI(idx))
	if err != nil {
		return fmt.Errorf("failed to open layer file: %w", err)
	}
	defer file.Close()
	if err := c.store.Push(ctx, c.turboOCILayers[idx], file); err != nil {
		return fmt.Errorf("failed to push layer: %w", err)
	}

	log.G(ctx).Infof("push layer-%d, elapsed: %.3f s", idx, time.Since(start).Seconds())
	return nil
}

func (c *convertor) prepareManifest() {
	for idx := range c.manifest.Layers {
		layer := c.manifestJSON.S("layers").Index(idx)
		layer.Set(c.turboOCILayers[idx].Digest, "digest")
		layer.Set(c.turboOCILayers[idx].Size, "size")
		layer.Set(ocispec.MediaTypeImageLayerGzip, "mediaType")
		if !layer.Exists("annotations") {
			layer.Object("annotations")
		}
		layer.S("annotations").Set(c.turboOCILayers[idx].Digest, label.OverlayBDBlobDigest)
		layer.S("annotations").Set(fmt.Sprintf("%d", c.turboOCILayers[idx].Size), label.OverlayBDBlobSize)
		layer.S("annotations").Set(c.manifest.Layers[idx].Digest, label.TurboOCIDigest)
		var targetMediaType string
		if dockerspec.IsDockerType(c.manifest.Layers[idx].MediaType) {
			if c.isGzipLayer[idx] {
				targetMediaType = dockerspec.MediaTypeDockerSchema2LayerGzip
			} else {
				targetMediaType = dockerspec.MediaTypeDockerSchema2Layer
			}
		} else {
			if c.isGzipLayer[idx] {
				targetMediaType = ocispec.MediaTypeImageLayerGzip
			} else {
				targetMediaType = ocispec.MediaTypeImageLayer
			}
		}
		layer.S("annotations").Set(targetMediaType, label.TurboOCIMediaType)
		layer.S("annotations").Set(version.TurboOCIVersionNumber, label.OverlayBDVersion)

		c.configJSON.S("rootfs", "diff_ids").SetIndex(c.turboOCIUncompressed[idx], idx)
	}
}

func (c *convertor) pushManifest(ctx context.Context) (ocispec.Descriptor, error) {
	// do not modify time for a reproducible config
	// c.configJSON.Set(time.Now(), "created")
	configDesc := internal.FromBytes(c.configJSON.Bytes())
	c.manifestJSON.S("config").Set(configDesc.Digest, "digest")
	c.manifestJSON.S("config").Set(configDesc.Size, "size")

	if c.ociFormat || c.manifest.MediaType == ocispec.MediaTypeImageManifest {
		internal.ConvertManifest(c.manifestJSON, internal.OCIFormat)
	} else {
		internal.ConvertManifest(c.manifestJSON, internal.DockerFormat)
	}
	manifestDesc := internal.FromBytes(c.manifestJSON.Bytes())
	manifestDesc.MediaType = c.manifestJSON.S("mediaType").Data().(string)

	if err := c.store.Push(ctx, configDesc, bytes.NewReader(c.configJSON.Bytes())); err != nil {
		return ocispec.DescriptorEmptyJSON, fmt.Errorf("failed to push config: %w", err)
	}
	log.G(ctx).WithFields(log.Fields{"digest": configDesc.Digest, "size": configDesc.Size}).Infof("config pushed")
	if err := c.store.Push(ctx, manifestDesc, bytes.NewReader(c.manifestJSON.Bytes())); err != nil {
		return ocispec.DescriptorEmptyJSON, fmt.Errorf("failed to push manifest: %w", err)
	}
	log.G(ctx).WithFields(log.Fields{"digest": manifestDesc.Digest, "size": manifestDesc.Size}).Infof("manifest pushed")
	return manifestDesc, nil
}

var (
	// referrer always use this config
	defaultConfigContent    = []byte("{}")
	defaultConfigDescriptor = ocispec.Descriptor{
		MediaType: ArtifactMediaType,
		Digest:    ocispec.DescriptorEmptyJSON.Digest,
		Size:      ocispec.DescriptorEmptyJSON.Size,
	}
)

func (c *convertor) pushReferrer(ctx context.Context) error {
	// deep clone
	referJSON, err := internal.ParseJSON(c.manifestJSON, nil)
	if err != nil {
		return fmt.Errorf("failed to clone referrer JSON: %w", err)
	}
	// config.mediaType will be used as ArtifactType
	referJSON.Object("config")
	referJSON.S("config").Set(defaultConfigDescriptor.Digest, "digest")
	referJSON.S("config").Set(defaultConfigDescriptor.Size, "size")
	referJSON.S("config").Set(defaultConfigDescriptor.MediaType, "mediaType")

	// referrers must in OCI format
	internal.ConvertManifest(referJSON, internal.OCIFormat)

	// subject
	referJSON.Object("subject")
	referJSON.S("subject").Set(c.src.MediaType, "mediaType")
	referJSON.S("subject").Set(c.src.Digest, "digest")
	referJSON.S("subject").Set(c.src.Size, "size")

	referDesc := internal.FromBytes(referJSON.Bytes())
	referDesc.MediaType = referJSON.S("mediaType").Data().(string)

	if err := c.store.Push(ctx, defaultConfigDescriptor, bytes.NewReader(defaultConfigContent)); err != nil {
		return fmt.Errorf("failed to push config (placeholder): %w", err)
	}
	log.G(ctx).WithFields(log.Fields{
		"digest": defaultConfigDescriptor.Digest,
		"size":   defaultConfigDescriptor.Size,
	}).Infof("config pushed")

	if err := c.store.Push(ctx, referDesc, bytes.NewReader(referJSON.Bytes())); err != nil {
		return fmt.Errorf("failed to push referrer: %w", err)
	}
	log.G(ctx).WithFields(log.Fields{"digest": referDesc.Digest, "size": referDesc.Size}).Infof("referrer pushed")
	return nil
}

const (
	overlaybdCreateBin = "/opt/overlaybd/bin/overlaybd-create"
	overlaybdApplyBin  = "/opt/overlaybd/bin/overlaybd-apply"
	overlaybdCommitBin = "/opt/overlaybd/bin/overlaybd-commit"

	turboOCIApplyBin = "/opt/overlaybd/bin/turboOCI-apply"
)

func (c *convertor) cmdCreate(ctx context.Context, idx int) error {
	args := []string{
		c.pathWritableData(idx),
		c.pathWritableIndex(idx),
		fmt.Sprintf("%d", c.vsize),
		"-s", "--turboOCI",
	}
	if idx == 0 {
		args = append(args, "--mkfs")
	}
	if out, err := exec.CommandContext(ctx, overlaybdCreateBin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to overlaybd-create: %w, output: %s", err, out)
	}
	file, err := os.OpenFile(c.pathLayerOCIv1(idx), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to create fake OCIv1 layer file: %w", err)
	}
	file.Close()
	c.devConfig.Upper = snapshot.OverlayBDBSConfigUpper{
		Data:   c.pathWritableData(idx),
		Index:  c.pathWritableIndex(idx),
		Target: c.pathLayerOCIv1(idx),
	}
	b, err := json.Marshal(c.devConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal device config: %w", err)
	}
	if err := os.WriteFile(c.pathLayerDeviceConfig(idx), b, 0644); err != nil {
		return fmt.Errorf("failed to write device config: %w", err)
	}
	return nil
}

func (c *convertor) cmdApply(ctx context.Context, idx int) error {
	args := []string{
		c.pathLayerOCIv1(idx),
		c.pathLayerDeviceConfig(idx),
		"--service_config_path", c.pathServiceConfig(),
		// (TODO) can't use checksum directly (apply on TurboOCI will do lseek),
		// maybe need some other way to check it.
		// "--checksum", c.config.RootFS.DiffIDs[idx].String(),
	}
	if c.isGzipLayer[idx] {
		args = append(args, "--gz_index_path", c.pathLayerGzipIndex(idx))
	}
	if out, err := exec.CommandContext(ctx, overlaybdApplyBin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to overlaybd-apply: %w, output: %s", err, out)
	}
	return nil
}

func (c *convertor) cmdApplyMeta(ctx context.Context, idx int) error {
	if c.metaFetcher == nil {
		return c.cmdApply(ctx, idx)
	}
	gzipIndex, tarMeta, err := c.metaFetcher.Fetch(ctx, c.manifest.Layers[idx])
	if err == ErrMetaNotFound {
		return c.cmdApply(ctx, idx)
	} else if err != nil {
		return fmt.Errorf("failed to fetch layer meta: %w", err)
	}
	defer gzipIndex.Close()
	defer tarMeta.Close()

	writeFile := func(name string, content io.Reader) error {
		file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()
		if _, err := io.Copy(file, content); err != nil {
			return fmt.Errorf("failed to write content: %w", err)
		}
		return nil
	}
	if c.isGzipLayer[idx] {
		if err := writeFile(c.pathLayerGzipIndex(idx), gzipIndex); err != nil {
			return fmt.Errorf("failed to write gzip index: %w", err)
		}
	}
	if err := writeFile(c.pathLayerTarMeta(idx), tarMeta); err != nil {
		return fmt.Errorf("failed to write tar meta: %w", err)
	}

	if out, err := exec.CommandContext(ctx, turboOCIApplyBin,
		c.pathLayerTarMeta(idx),
		c.pathLayerDeviceConfig(idx),
		"--import",
		"--service_config_path", c.pathServiceConfig(),
	).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to turboOCI-apply: %w, output: %s", err, out)
	}
	return nil
}

func (c *convertor) cmdCommit(ctx context.Context, idx int) error {
	if out, err := exec.CommandContext(ctx, overlaybdCommitBin,
		c.pathWritableData(idx),
		c.pathWritableIndex(idx),
		c.pathLayerFSMeta(idx),
		"-z", "--turboOCI",
		"--uuid", internal.ChainIDtoUUID(c.chainIDs[idx]),
	).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to overlaybd-commit: %w, output: %s", err, out)
	}
	lower := snapshot.OverlayBDBSConfigLower{
		TargetFile:   c.pathLayerOCIv1(idx),
		TargetDigest: c.manifest.Layers[idx].Digest.String(), // TargetDigest should be set to work with gzip cache
		File:         c.pathLayerFSMeta(idx),
	}
	if c.isGzipLayer[idx] {
		lower.GzipIndex = c.pathLayerGzipIndex(idx)
	}
	c.devConfig.Lowers = append(c.devConfig.Lowers, lower)
	return nil
}
