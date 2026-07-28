// AIVisor Kubernetes controller
//
// This is a Go controller using controller-runtime that reconciles
// AIVisorSandbox, SandboxTemplate, and WarmPool CRDs.
//
// Build: go build -o aivisor-controller ./k8s/controller/
//
// Requires: Go 1.22+, controller-runtime v0.19+

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// TODO: Add AIVisor CRD types to scheme
}

// AIVisorSandboxReconciler reconciles AIVisorSandbox resources.
type AIVisorSandboxReconciler struct {
	client.Client
}

func (r *AIVisorSandboxReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.Log.WithValues("aivisorsandbox", req.NamespacedName)
	log.Info("Reconciling AIVisorSandbox")

	// TODO(phase4): call aivisord gRPC CreateSandbox/DestroySandbox
	// based on the CR's current state and finalizer.

	return ctrl.Result{}, nil
}

func main() {
	var metricsAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		LeaderElection:         true,
		LeaderElectionID:       "aivisor-controller.aivisor.dev",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&AIVisorSandboxReconciler{}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func (r *AIVisorSandboxReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&AIVisorSandboxReconciler{}).
		Complete(r)
}
