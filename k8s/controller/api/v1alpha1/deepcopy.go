// DeepCopy implementations for the aivisor.dev v1alpha1 types.
//
// Hand-written rather than generated: the repository does not run
// controller-gen as part of its build, and a checked-in generated file that
// nothing regenerates drifts silently from the types beside it. These are
// small and mechanical — when you add a field to types.go, add it here too.
// The rule is the usual one for runtime.Object: every pointer, slice and map
// must be copied, never aliased, or two reconcile loops end up mutating the
// same backing array through what they each believe is their own copy.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func (in *AIVisorSandboxSpec) DeepCopyInto(out *AIVisorSandboxSpec) {
	*out = *in
	if in.Policy != nil {
		out.Policy = in.Policy.DeepCopy()
	}
	if in.Env != nil {
		out.Env = make(map[string]string, len(in.Env))
		for k, v := range in.Env {
			out.Env[k] = v
		}
	}
}

func (in *AIVisorSandboxSpec) DeepCopy() *AIVisorSandboxSpec {
	if in == nil {
		return nil
	}
	out := new(AIVisorSandboxSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *AIVisorSandboxStatus) DeepCopyInto(out *AIVisorSandboxStatus) {
	*out = *in
	if in.SnapshotRefs != nil {
		out.SnapshotRefs = make([]string, len(in.SnapshotRefs))
		copy(out.SnapshotRefs, in.SnapshotRefs)
	}
}

func (in *AIVisorSandboxStatus) DeepCopy() *AIVisorSandboxStatus {
	if in == nil {
		return nil
	}
	out := new(AIVisorSandboxStatus)
	in.DeepCopyInto(out)
	return out
}

func (in *AIVisorSandbox) DeepCopyInto(out *AIVisorSandbox) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *AIVisorSandbox) DeepCopy() *AIVisorSandbox {
	if in == nil {
		return nil
	}
	out := new(AIVisorSandbox)
	in.DeepCopyInto(out)
	return out
}

func (in *AIVisorSandbox) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *AIVisorSandboxList) DeepCopyInto(out *AIVisorSandboxList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AIVisorSandbox, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *AIVisorSandboxList) DeepCopy() *AIVisorSandboxList {
	if in == nil {
		return nil
	}
	out := new(AIVisorSandboxList)
	in.DeepCopyInto(out)
	return out
}

func (in *AIVisorSandboxList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *SandboxTemplateSpec) DeepCopyInto(out *SandboxTemplateSpec) {
	*out = *in
	if in.ResourceDefaults != nil {
		out.ResourceDefaults = in.ResourceDefaults.DeepCopy()
	}
}

func (in *SandboxTemplateSpec) DeepCopy() *SandboxTemplateSpec {
	if in == nil {
		return nil
	}
	out := new(SandboxTemplateSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *SandboxTemplate) DeepCopyInto(out *SandboxTemplate) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *SandboxTemplate) DeepCopy() *SandboxTemplate {
	if in == nil {
		return nil
	}
	out := new(SandboxTemplate)
	in.DeepCopyInto(out)
	return out
}

func (in *SandboxTemplate) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *SandboxTemplateList) DeepCopyInto(out *SandboxTemplateList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SandboxTemplate, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *SandboxTemplateList) DeepCopy() *SandboxTemplateList {
	if in == nil {
		return nil
	}
	out := new(SandboxTemplateList)
	in.DeepCopyInto(out)
	return out
}

func (in *SandboxTemplateList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
