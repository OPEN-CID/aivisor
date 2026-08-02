// Package v1alpha1 contains the Go types for the aivisor.dev CRDs.
//
// These mirror k8s/crds/*.yaml. When a field changes in one, it must change in
// the other: the CRD's openAPIV3Schema is what the API server validates
// against, and these structs are what the controller decodes into. A field
// present here but absent from the CRD schema is silently dropped by the API
// server (structural schema pruning), which looks like the controller reading
// an empty value rather than like an error.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the group/version these types are served under.
var GroupVersion = schema.GroupVersion{Group: "aivisor.dev", Version: "v1alpha1"}

// SchemeBuilder registers these types with a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds these types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// AIVisorSandboxSpec is the desired state of a sandbox.
type AIVisorSandboxSpec struct {
	// Template names the SandboxTemplate to launch from. Required.
	Template string `json:"template"`

	// Policy is the sandbox policy document. Held as RawExtension because the
	// CRD schema declares it as a free-form object: it is parsed by
	// aivisor-policy on the node, not by this controller.
	Policy *runtime.RawExtension `json:"policy,omitempty"`

	// Env is passed through to the sandbox process environment.
	Env map[string]string `json:"env,omitempty"`

	// Timeout is a Go-style duration string (e.g. "30m").
	Timeout string `json:"timeout,omitempty"`
}

// AIVisorSandboxStatus is the observed state of a sandbox.
type AIVisorSandboxStatus struct {
	Phase        string   `json:"phase,omitempty"`
	SandboxID    string   `json:"sandboxId,omitempty"`
	CgroupID     uint64   `json:"cgroupId,omitempty"`
	Node         string   `json:"node,omitempty"`
	SnapshotRefs []string `json:"snapshotRefs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AIVisorSandbox is one confined workload managed by aivisord.
type AIVisorSandbox struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AIVisorSandboxSpec   `json:"spec,omitempty"`
	Status AIVisorSandboxStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AIVisorSandboxList is a list of AIVisorSandbox.
type AIVisorSandboxList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AIVisorSandbox `json:"items"`
}

// SandboxTemplateSpec is the desired state of a template.
type SandboxTemplateSpec struct {
	// BaseImage is the rootfs template name. Required.
	BaseImage string `json:"baseImage"`

	DefaultPolicy string `json:"defaultPolicy,omitempty"`

	// WarmPoolSize defaults to 5 in the CRD schema.
	WarmPoolSize int32 `json:"warmPoolSize,omitempty"`

	ResourceDefaults *runtime.RawExtension `json:"resourceDefaults,omitempty"`
}

// +kubebuilder:object:root=true

// SandboxTemplate describes a rootfs template and its defaults.
type SandboxTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SandboxTemplateSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// SandboxTemplateList is a list of SandboxTemplate.
type SandboxTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&AIVisorSandbox{}, &AIVisorSandboxList{},
		&SandboxTemplate{}, &SandboxTemplateList{},
	)
}
