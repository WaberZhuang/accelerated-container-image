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
	"encoding/json"
	"fmt"
	"io"

	"github.com/Jeffail/gabs/v2"
	"github.com/containerd/containerd/errdefs"
)

// Data should be { io.Reader | []byte | *gabs.Container | struct object pointed by target }
//
// Note:
//  1. For *gabs.Container, return value will be a deep copy of it
func ParseJSON(data any, target any) (*gabs.Container, error) {
	toBytes := func(data any) ([]byte, error) {
		switch v := data.(type) {
		case nil:
			return nil, errdefs.ErrInvalidArgument
		case string:
			return []byte(v), nil
		case []byte:
			return v, nil
		case io.Reader:
			b, err := io.ReadAll(v)
			if err != nil {
				return nil, fmt.Errorf("failed to read data: %w", err)
			}
			return b, nil
		case *gabs.Container:
			return v.Bytes(), nil
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal data: %w", err)
			}
			return b, nil
		}
	}
	dataBytes, err := toBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data to bytes: %w", err)
	}
	if target != nil {
		if err := json.Unmarshal(dataBytes, target); err != nil {
			return nil, fmt.Errorf("failed to unmarshal: %w", err)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(dataBytes))
	dec.UseNumber()
	jbuf, err := gabs.ParseJSONDecoder(dec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse to gabs: %w", err)
	}
	return jbuf, nil
}
