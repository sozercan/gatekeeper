/*

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

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConnectionAllowsRuntimeSource(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		connection *Connection
		want       bool
	}{
		"nil": {},
		"explicit runtime": {
			connection: &Connection{Spec: ConnectionSpec{Sources: []ConnectionSource{RuntimeSource}}},
			want:       true,
		},
		"managed CRD annotation fallback": {
			connection: &Connection{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{RuntimeSourceAnnotation: string(RuntimeSource)}}},
			want:       true,
		},
		"missing source": {
			connection: &Connection{},
		},
		"wrong annotation value": {
			connection: &Connection{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{RuntimeSourceAnnotation: string(AuditSource)}}},
		},
		"explicit audit overrides annotation": {
			connection: &Connection{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{RuntimeSourceAnnotation: string(RuntimeSource)}},
				Spec:       ConnectionSpec{Sources: []ConnectionSource{AuditSource}},
			},
		},
		"mixed explicit sources are rejected": {
			connection: &Connection{Spec: ConnectionSpec{Sources: []ConnectionSource{RuntimeSource, AuditSource}}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := test.connection.AllowsRuntimeSource(); got != test.want {
				t.Fatalf("AllowsRuntimeSource() = %t, want %t", got, test.want)
			}
		})
	}
}
