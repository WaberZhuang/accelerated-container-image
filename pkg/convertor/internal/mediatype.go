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
	"fmt"

	"github.com/Jeffail/gabs/v2"
	dockerspec "github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type MediaTypeFormat int

const (
	OCIFormat MediaTypeFormat = iota
	DockerFormat
)

var toDocker = map[string]string{
	ocispec.MediaTypeImageManifest:  dockerspec.MediaTypeDockerSchema2Manifest,
	ocispec.MediaTypeImageConfig:    dockerspec.MediaTypeDockerSchema2Config,
	ocispec.MediaTypeImageLayerGzip: dockerspec.MediaTypeDockerSchema2LayerGzip,
}

var toOCI map[string]string

func init() {
	toOCI = make(map[string]string)
	for k, v := range toDocker {
		toOCI[v] = k
	}
}

func (format MediaTypeFormat) parse(mediaType string) string {
	var mp map[string]string
	switch format {
	case OCIFormat:
		mp = toOCI
	case DockerFormat:
		mp = toDocker
	}
	if mediaType, ok := mp[mediaType]; ok {
		return mediaType
	}
	return mediaType
}

func (format MediaTypeFormat) set(g *gabs.Container, hierarchy ...string) {
	if g.Exists(hierarchy...) {
		if mediaType, ok := g.S(hierarchy...).Data().(string); ok {
			g.Set(format.parse(mediaType), hierarchy...)
		}
	}
}

func ConvertManifest(manifest *gabs.Container, format MediaTypeFormat) {
	format.set(manifest, "mediaType")
	format.set(manifest, "config", "mediaType")
	if manifest.Exists("layers") {
		for _, layer := range manifest.S("layers").Children() {
			format.set(layer, "mediaType")
		}
	}
}

func ParseFormat(mediaType string) (MediaTypeFormat, error) {
	if _, ok := toOCI[mediaType]; ok {
		return DockerFormat, nil
	}
	if _, ok := toDocker[mediaType]; ok {
		return OCIFormat, nil
	}
	return OCIFormat, fmt.Errorf("unknown media type %s", mediaType)
}
