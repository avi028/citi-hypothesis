// v1convert — converts qualys.com/v1 RuntimePolicy YAML into the Cilium
// TracingPolicy YAML that the operator would send to the agent.
//
// This mirrors PolicyReconciler.convertCRDPolicyToEBPFAgentPolicy: it parses
// each v1 document, validates the spec the same way, then calls the exact
// Create*Policy builders used by the real reconcile path — so the output
// is byte-for-byte what the agent would receive in a cluster.
//
// Usage:
//   go run ./citi-hypothesis/tools/v1convert < policy-v1.yaml > out-tp.yaml
//   ./tetra tracingpolicy add out-tp.yaml
package main

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"

	ciliumv1alpha1 "github.com/cilium/ebpf-agent/pkg/k8s/apis/cilium.io/v1alpha1"
	policyV1 "github.com/cilium/ebpf-agent/pkg/operator/api/v1"
	"github.com/cilium/ebpf-agent/pkg/operator/controllers"
)

// convert mirrors validateCRDPolicy + the base-policy switch in
// tracingpolicy_controller.go.
func convert(spec *policyV1.RuntimePolicySpec, name string) (*ciliumv1alpha1.TracingPolicy, error) {
	bp := spec.BasePolicy
	if bp == "" {
		return nil, fmt.Errorf("BasePolicy is not set")
	}
	switch {
	case strings.HasPrefix(bp, "net-"):
		if len(spec.GetMonitorPaths()) > 0 {
			return nil, fmt.Errorf("MonitorPaths not required for network policies")
		}
	case strings.HasPrefix(bp, "file-"):
		if len(spec.GetMonitorPaths()) == 0 {
			return nil, fmt.Errorf("MonitorPaths is must for file policies")
		}
	case strings.HasPrefix(bp, "qualys-"):
		if len(spec.GetMonitorPaths()) == 0 && len(spec.GetMonitorDestIPs()) == 0 {
			return nil, fmt.Errorf("monitor-paths or monitor-dest-ips required for %s policy", bp)
		}
	default:
		return nil, fmt.Errorf("Unknown base policy type: %s", bp)
	}

	switch bp {
	case "net-tcp-open":
		return controllers.CreateNetOpenPolicy(spec, name), nil
	case "file-open":
		return controllers.CreateOpenPolicy(spec, name), nil
	case "file-delete":
		return controllers.CreateDeletePolicy(spec, name), nil
	case "file-read":
		return controllers.CreateReadPolicy(spec, name), nil
	case "file-write":
		return controllers.CreateWritePolicy(spec, name, false), nil
	case "file-write-diff":
		return controllers.CreateWritePolicy(spec, name, true), nil
	case "file-rename":
		return controllers.CreateRenamePolicy(spec, name), nil
	case "file-create":
		return controllers.CreateCreatePolicy(spec, name), nil
	case "file-metadata":
		return controllers.CreateFileMetadataPolicy(spec, name), nil
	case "file-links":
		return controllers.CreateFileLinksPolicy(spec, name), nil
	case "qualys-delete":
		return controllers.CreateQualysDeletePolicy(spec, name), nil
	case "qualys-accept":
		return controllers.CreateQualysAcceptPolicy(spec, name), nil
	case "qualys-connect":
		return controllers.CreateQualysConnectPolicy(spec, name), nil
	case "qualys-rename":
		return controllers.CreateQualysRenamePolicy(spec, name), nil
	}
	return nil, fmt.Errorf("Unknown base policy type: %s", bp)
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if len(os.Args) < 2 || err != nil {
		fmt.Fprintf(os.Stderr, "usage: v1convert <policy-v1.yaml>\n%v\n", err)
		os.Exit(2)
	}
	first := true
	for _, doc := range strings.Split(string(data), "\n---") {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var rp policyV1.RuntimePolicy
		if err := yaml.Unmarshal([]byte(doc), &rp); err != nil {
			fmt.Fprintf(os.Stderr, "bad document: %v\n", err)
			os.Exit(1)
		}
		tp, err := convert(&rp.Spec, rp.GetName())
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", rp.GetName(), err)
			os.Exit(1)
		}
		out, err := yaml.Marshal(tp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: marshal: %v\n", rp.GetName(), err)
			os.Exit(1)
		}
		if !first {
			fmt.Println("---")
		}
		first = false
		fmt.Print(string(out))
	}
}
