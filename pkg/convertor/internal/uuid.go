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

	"github.com/opencontainers/go-digest"
)

// UUID: 8-4-4-4-12
func ChainIDtoUUID(chainID digest.Digest) string {
	dStr := chainID[7:]
	return fmt.Sprintf("%s-%s-%s-%s-%s", dStr[0:8], dStr[8:12], dStr[12:16], dStr[16:20], dStr[20:32])
}