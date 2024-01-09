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

package internal

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// ignore non-existent file
// return (compressed desc, uncompressed desc, error)
func BuildArchiveFromFiles(ctx context.Context, target string, compress compression.Compression, files ...string) (ocispec.Descriptor, ocispec.Descriptor, error) {
	dwCompressed := NewDescWriter(sha256.New())
	dwUncompressed := NewDescWriter(sha256.New())

	build := func() error {
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		archive, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("failed to create target file: %w", err)
		}
		defer archive.Close()

		fzip, err := compression.CompressStream(io.MultiWriter(archive, dwCompressed), compress)
		if err != nil {
			return fmt.Errorf("failed to create compression stream: %w", err)
		}
		defer fzip.Close()

		ftar := tar.NewWriter(io.MultiWriter(fzip, dwUncompressed))
		defer ftar.Close()
		for _, file := range files {
			if err := addFileToArchive(ctx, ftar, file); err != nil {
				return fmt.Errorf("failed to add file %q: %w", file, err)
			}
		}
		return nil
	}
	if err := build(); err != nil {
		return ocispec.DescriptorEmptyJSON, ocispec.DescriptorEmptyJSON, err
	}

	return dwCompressed.Descriptor(), dwUncompressed.Descriptor(), nil
}

func addFileToArchive(ctx context.Context, ftar *tar.Writer, filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return fmt.Errorf("failed to parse file info to tar header: %w", err)
	}
	// remove timestamp for consistency
	if err = ftar.WriteHeader(&tar.Header{
		Name:     header.Name,
		Mode:     header.Mode,
		Size:     header.Size,
		Typeflag: header.Typeflag,
	}); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if header.Typeflag == tar.TypeReg {
		_, err = io.Copy(ftar, file)
		if err != nil {
			return fmt.Errorf("failed to write tar data: %w", err)
		}
	}
	return nil
}
