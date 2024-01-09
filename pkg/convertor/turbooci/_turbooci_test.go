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

package turbooci_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/accelerated-container-image/cmd/convertor/testingresources"
	"github.com/containerd/accelerated-container-image/pkg/convertor/internal"
	"github.com/containerd/accelerated-container-image/pkg/convertor/turbooci"
	"github.com/containerd/accelerated-container-image/pkg/label"
	"github.com/containerd/accelerated-container-image/pkg/version"
	"github.com/containerd/containerd/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasmemory "oras.land/oras-go/v2/content/memory"
)

type MockRegistry struct {
	oras.Target
	referrers sync.Map
}

type referKey struct {
	dgst         digest.Digest
	artifactType string
}

const MediaTypeArtifactManifest = "application/vnd.oci.artifact.manifest.v1+json"

func (mr *MockRegistry) Push(ctx context.Context, expected ocispec.Descriptor, content io.Reader) error {
	buf := bytes.NewBuffer(nil)
	if expected.MediaType == ocispec.MediaTypeImageManifest || expected.MediaType == MediaTypeArtifactManifest {
		content = io.TeeReader(content, buf)
	}

	if err := mr.Target.Push(ctx, expected, content); err != nil {
		return err
	}
	if expected.MediaType == ocispec.MediaTypeImageManifest || expected.MediaType == MediaTypeArtifactManifest {
		var manifest ocispec.Manifest
		if _, err := internal.ParseJSON(buf.Bytes(), &manifest); err != nil {
			return fmt.Errorf("failed to parse manifest: %w", err)
		}
		if manifest.Subject != nil {
			artifactType := ""
			if manifest.ArtifactType != "" {
				artifactType = manifest.ArtifactType
			} else {
				artifactType = manifest.Config.MediaType
			}
			key := referKey{manifest.Subject.Digest, artifactType}

			referrers, ok := mr.referrers.Load(key)
			if !ok {
				referrers = []ocispec.Descriptor{expected}
			} else {
				referrers = append(referrers.([]ocispec.Descriptor), expected)
			}
			mr.referrers.Store(key, referrers)
		}
	}
	return nil
}

func (mr *MockRegistry) Referrers(ctx context.Context, desc ocispec.Descriptor, artifactType string, fn func(referrers []ocispec.Descriptor) error) error {
	if referrers, ok := mr.referrers.Load(referKey{desc.Digest, artifactType}); ok {
		return fn(referrers.([]ocispec.Descriptor))
	} else {
		return fn(nil)
	}
}

// Note:
//  1. Not support multi-arch images for now
func (mr *MockRegistry) PrepareImageFromResolver(ctx context.Context, resolver remotes.Resolver, ref string) error {
	_, manifestDesc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("failed to resolve tag: %w", err)
	}
	fetcher, err := resolver.Fetcher(ctx, ref)
	if err != nil {
		return fmt.Errorf("failed to new fetcher: %w", err)
	}
	rc, err := fetcher.Fetch(ctx, manifestDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()
	var manifest ocispec.Manifest
	if _, err := internal.ParseJSON(rc, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	copyBlob := func(desc ocispec.Descriptor) error {
		rc, err = fetcher.Fetch(ctx, desc)
		if err != nil {
			return fmt.Errorf("failed to fetch %q: %w", desc.Digest, err)
		}
		defer rc.Close()
		if err := mr.Push(ctx, desc, rc); err != nil {
			return fmt.Errorf("failed to push %q: %w", desc.Digest, err)
		}
		return nil
	}
	if err := copyBlob(manifest.Config); err != nil {
		return fmt.Errorf("failed to copy config: %w", err)
	}
	for idx, layer := range manifest.Layers {
		if err := copyBlob(layer); err != nil {
			return fmt.Errorf("failed to copy layer-%d: %w", idx, err)
		}
	}
	if err := copyBlob(manifestDesc); err != nil {
		return fmt.Errorf("failed to copy manifest: %w", err)
	}
	if err := mr.Tag(ctx, manifestDesc, ref); err != nil {
		return fmt.Errorf("failed to tag %q: %w", ref, err)
	}
	return nil
}

type Checker interface {
	Check(ctx context.Context, t *testing.T, store *MockRegistry, src ocispec.Descriptor, turbo ocispec.Descriptor)
}

type ManifestChecker struct {
	format internal.MediaTypeFormat
}

func (checker *ManifestChecker) Check(ctx context.Context, t *testing.T, store *MockRegistry, src ocispec.Descriptor, turbo ocispec.Descriptor) {
	var srcManifest ocispec.Manifest
	rc, err := store.Fetch(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := internal.ParseJSON(rc, &srcManifest); err != nil {
		t.Fatal(err)
	}

	var turboManifest ocispec.Manifest
	rc, err = store.Fetch(ctx, turbo)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	turboManifestJSON, err := internal.ParseJSON(rc, &turboManifest)
	if err != nil {
		t.Fatal(err)
	}

	assert := assert.New(t)

	// check mediaType format
	beforeFormat := turboManifestJSON.Bytes()
	internal.ConvertManifest(turboManifestJSON, checker.format)
	afterFormat := turboManifestJSON.Bytes()
	assert.Equal(true, bytes.Equal(beforeFormat, afterFormat), "mediaType format")

	// check turbo manifest
	assert.Equal(len(srcManifest.Layers), len(turboManifest.Layers))
	for idx := range turboManifest.Layers {
		srcLayer := srcManifest.Layers[idx]
		turboLayer := turboManifest.Layers[idx]
		assert.Equal(srcLayer.MediaType, turboLayer.Annotations[label.TurboOCIMediaType], "target media type")
		assert.Equal(srcLayer.Digest.String(), turboLayer.Annotations[label.TurboOCIDigest], "target digest")
		assert.Equal(version.TurboOCIVersionNumber, turboLayer.Annotations[label.OverlayBDVersion], "version number")

		assert.Equal(turboLayer.Digest.String(), turboLayer.Annotations[label.OverlayBDBlobDigest], "overlaybd digest")
		assert.Equal(fmt.Sprintf("%d", turboLayer.Size), turboLayer.Annotations[label.OverlayBDBlobSize], "overlaybd size")
	}

	// (TODO) check diffIDs
}

type ReferrerChecker struct{}

func (checker *ReferrerChecker) Check(ctx context.Context, t *testing.T, store *MockRegistry, src ocispec.Descriptor, turbo ocispec.Descriptor) {
	refers := []ocispec.Descriptor{}
	if err := store.Referrers(ctx, src, turbooci.ArtifactMediaType, func(referrers []ocispec.Descriptor) error {
		refers = append(refers, referrers...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	assert := assert.New(t)
	assert.Equal(1, len(refers))
	rc, err := store.Fetch(ctx, refers[0])
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var manifest ocispec.Manifest
	if _, err := internal.ParseJSON(rc, &manifest); err != nil {
		t.Fatal(err)
	}
	assert.Equal(turbooci.ArtifactMediaType, manifest.Config.MediaType, "artifact type")
	assert.Equal(ocispec.DescriptorEmptyJSON.Digest, manifest.Config.Digest)
	assert.Equal(ocispec.DescriptorEmptyJSON.Size, manifest.Config.Size)

	assert.Equal(src.Digest, manifest.Subject.Digest, "subject digest")
	assert.Equal(src.MediaType, manifest.Subject.MediaType, "subject media type")
	assert.Equal(src.Size, manifest.Subject.Size, "subject size")
}

type MockMetaFetcher struct {
	store   content.ReadOnlyStorage
	workdir string
}

func (fetcher *MockMetaFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, io.ReadCloser, error) {
	rc, err := fetcher.store.Fetch(ctx, desc)
	if err != nil {
		return nil, nil, err
	}
	defer rc.Close()
	fnLayer := filepath.Join(fetcher.workdir, desc.Digest.Encoded())
	file, err := os.OpenFile(fnLayer, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, nil, err
	}
	if _, err := io.Copy(file, rc); err != nil {
		return nil, nil, err
	}
	fnGzipIndex := filepath.Join(fetcher.workdir, desc.Digest.Encoded()+".gzip_index")
	fnTarMeta := filepath.Join(fetcher.workdir, desc.Digest.Encoded()+".tar_meta")
	if out, err := exec.CommandContext(ctx, "/opt/overlaybd/bin/turboOCI-apply",
		fnLayer, fnTarMeta, "--gz_index_path", fnGzipIndex, "--export",
	).CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("out: %s, err: %w", out, err)
	}
	gzipIndex, err := os.Open(fnGzipIndex)
	if err != nil {
		return nil, nil, err
	}
	tarMeta, err := os.Open(fnTarMeta)
	if err != nil {
		return nil, nil, err
	}
	return gzipIndex, tarMeta, nil
}

type MockMetaFetcherNotFound struct{}

func (fetcher *MockMetaFetcherNotFound) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, io.ReadCloser, error) {
	return nil, nil, turbooci.ErrMetaNotFound
}

func TestConvertTurboOCI(t *testing.T) {
	store := &MockRegistry{
		Target: orasmemory.New(),
	}

	metaDir := filepath.Join("/tmp", "accelerated-container-image", "meta")
	if err := os.MkdirAll(metaDir, 0755); err != nil {
		t.Fatal(err)
	}

	testcases := []struct {
		name      string
		reference string
		options   []turbooci.ConvertOption
		checkers  []Checker
	}{
		{
			name:      "convert to manifest",
			reference: testingresources.DockerV2_Manifest_Simple_Ref,
			options: []turbooci.ConvertOption{
				turbooci.WithManifestFormat(true),
			},
			checkers: []Checker{&ManifestChecker{internal.DockerFormat}},
		},
		{
			name:      "convert in oci format",
			reference: testingresources.DockerV2_Manifest_Simple_Ref,
			options: []turbooci.ConvertOption{
				turbooci.WithManifestFormat(true),
				turbooci.WithOCIFormat(true),
			},
			checkers: []Checker{&ManifestChecker{internal.OCIFormat}},
		},
		{
			name:      "convert to referrer",
			reference: testingresources.DockerV2_Manifest_Simple_Ref,
			options: []turbooci.ConvertOption{
				turbooci.WithReferrerFormat(true),
			},
			checkers: []Checker{&ReferrerChecker{}},
		},
		{
			name:      "convert with meta fetcher",
			reference: testingresources.DockerV2_Manifest_Simple_Ref,
			options: []turbooci.ConvertOption{
				turbooci.WithManifestFormat(true),
				turbooci.WithMetaFetcher(&MockMetaFetcher{
					store:   store,
					workdir: metaDir,
				}),
			},
			checkers: []Checker{&ManifestChecker{internal.DockerFormat}},
		},
		{
			name:      "convert with meta fetcher fall back",
			reference: testingresources.DockerV2_Manifest_Simple_Ref,
			options: []turbooci.ConvertOption{
				turbooci.WithManifestFormat(true),
				turbooci.WithMetaFetcher(&MockMetaFetcherNotFound{}),
			},
			checkers: []Checker{&ManifestChecker{internal.DockerFormat}},
		},
	}

	ctx := context.Background()
	resolver, err := testingresources.NewMockLocalResolver(context.Background(),
		filepath.Join("..", "..", "..", "cmd", "convertor", "testingresources", "mocks", "registry"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// reset store
			store.Target = orasmemory.New()
			store.referrers = sync.Map{}

			if err := store.PrepareImageFromResolver(ctx, resolver, tc.reference); err != nil {
				t.Fatal(err)
			}
			src, err := store.Resolve(ctx, tc.reference)
			if err != nil {
				t.Fatal(err)
			}
			tc.options = append(tc.options, turbooci.WithWorkdir(filepath.Join(
				"/tmp",
				"accelerated-container-image",
				strings.ReplaceAll(t.Name(), " ", "-"),
			)))
			turbo, err := turbooci.Convert(ctx, src, store, tc.options...)
			if err != nil {
				t.Fatal(err)
			}
			for _, checker := range tc.checkers {
				checker.Check(ctx, t, store, src, turbo)
			}
		})
	}
}
