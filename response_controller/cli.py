"""Command Line Interface for Kubernetes Security Incident Management."""

import argparse
import sys
from response_controller.k8s_client import KubernetesClient


def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes Incident Response & Pod Remediation CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # List Command
    list_parser = subparsers.add_parser("list", help="List all quarantined pods")
    list_parser.add_argument("-n", "--namespace", help="Namespace to filter (optional)")

    # Unquarantine Command
    unq_parser = subparsers.add_parser("unquarantine", help="Lift quarantine from a pod")
    unq_parser.add_argument("namespace", help="Pod namespace")
    unq_parser.add_argument("pod", help="Pod name")

    args = parser.parse_args()
    k8s = KubernetesClient()

    if args.command == "list":
        pods = k8s.list_quarantined_pods(namespace=args.namespace)
        if not pods:
            print("No quarantined pods found.")
            return

        print(f"{'NAMESPACE':<15} {'POD NAME':<35} {'STATUS':<12} {'QUARANTINED AT'}")
        print("-" * 80)
        for p in pods:
            print(f"{p['namespace']:<15} {p['name']:<35} {p['status']:<12} {p['quarantined_at']}")

    elif args.command == "unquarantine":
        policy_name = f"quarantine-{args.pod}"
        print(f"Removing quarantine NetworkPolicy '{policy_name}' in namespace '{args.namespace}'...")
        try:
            k8s.networking_v1.delete_namespaced_network_policy(name=policy_name, namespace=args.namespace)
            print(f"NetworkPolicy '{policy_name}' removed.")
        except Exception as e:
            print(f"Warning removing policy: {e}")

        print(f"Updating metadata for pod '{args.pod}'...")
        labels = {"security.incident/quarantined": "false", "security.incident/status": "remediated"}
        annotations = {"security.incident/action": "quarantine-lifted"}
        success = k8s.patch_pod_metadata(namespace=args.namespace, pod_name=args.pod, labels=labels, annotations=annotations)
        if success:
            print(f"Pod '{args.namespace}/{args.pod}' successfully remediated.")
        else:
            print(f"Failed to patch pod metadata for '{args.pod}'.")
            sys.exit(1)


if __name__ == "__main__":
    main()
