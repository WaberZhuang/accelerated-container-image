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
	"bytes"
	"crypto/sha256"
	"hash"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func FromReader(r io.Reader) ocispec.Descriptor {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		panic(err)
	}
	return ocispec.Descriptor{
		Digest: digest.NewDigest(digest.SHA256, h),
		Size:   n,
	}
}

func FromBytes(b []byte) ocispec.Descriptor {
	return FromReader(bytes.NewReader(b))
}

type DescWriter struct {
	h    hash.Hash
	size int64
}

func (dw *DescWriter) Write(p []byte) (int, error) {
	n, err := dw.h.Write(p)
	dw.size += int64(n)
	return n, err
}

func (dw *DescWriter) Descriptor() ocispec.Descriptor {
	return ocispec.Descriptor{
		Digest: digest.NewDigest(digest.SHA256, dw.h),
		Size:   dw.size,
	}
}

func NewDescWriter(h hash.Hash) *DescWriter {
	return &DescWriter{
		h:    h,
		size: 0,
	}
}
