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

package internal_test

import (
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/accelerated-container-image/pkg/convertor/internal"
	"github.com/containerd/containerd/archive/compression"
	_ "github.com/containerd/containerd/pkg/testutil" // Handle custom root flag
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestTar(t *testing.T) {
	workspace := filepath.Join("/tmp", "accelerated-container-image", "tar_test")

	build := func(algo compression.Compression) (ocispec.Descriptor, ocispec.Descriptor) {
		files := []string{}
		gen := func(fn string, size int) {
			fn = filepath.Join(workspace, fn)
			buf := make([]byte, size)
			n, err := rand.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if n != size {
				t.Fatal(err)
			}
			if err := os.WriteFile(fn, buf, 0644); err != nil {
				t.Fatal(err)
			}
			files = append(files, fn)
		}
		os.RemoveAll(workspace)
		os.MkdirAll(workspace, 0755)
		gen("1.blob", 1024*1024)
		gen("2.blob", 10)
		gen("3.blob", 511)
		gen("4.blob", 512)
		gen("5.blob", 513)
		gen("6.blob", 1000*1000)

		ctx := context.Background()

		target := filepath.Join(workspace, "test.tar")
		descCompressed, descUncompressed, err := internal.BuildArchiveFromFiles(ctx, target, algo, files...)
		if err != nil {
			t.Fatal(err)
		}

		file, err := os.Open(target)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		descCompressedExpected := internal.FromReader(file)
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		drc, err := compression.DecompressStream(file)
		if err != nil {
			t.Fatal(err)
		}
		defer drc.Close()
		descUncompressedExpected := internal.FromReader(drc)

		assert.Equal(t, algo, drc.GetCompression())
		assert.Equal(t, descCompressedExpected, descCompressed)
		assert.Equal(t, descUncompressedExpected, descUncompressed)

		return descCompressedExpected, descUncompressedExpected
	}

	t.Run("gzip", func(t *testing.T) {
		build(compression.Gzip)
	})
	t.Run("uncompressed", func(t *testing.T) {
		d1, d2 := build(compression.Uncompressed)
		assert.Equal(t, d1, d2)
	})
}
