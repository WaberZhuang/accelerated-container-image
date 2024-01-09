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
	"context"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type MetaFetcher interface {
	// return (gzip_index, tar_meta, error). if gzip index is not needed, should return
	// io.NopCloser(nil) instead.
	Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, io.ReadCloser, error)
}

var ErrMetaNotFound = fmt.Errorf("meta not found")
