package k8s.security

# Define required labels
required_labels := {"owner", "environment"}

# --- Rule 1: Deny containers running as root
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container '%s' must not run as root", [container.name])
}

# --- Rule 2: Deny privileged containers
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Container '%s' must not be privileged", [container.name])
}

# --- Rule 3: Deny hostPath volumes
deny[msg] {
  input.kind == "Pod"
  volume := input.spec.volumes[_]
  volume.hostPath
  msg := "Use of hostPath volumes is not allowed due to security risk"
}

# --- Rule 4: Require specific labels (owner, environment)
deny[msg] {
  input.kind == "Pod"
  label := required_labels[_]
  not input.metadata.labels[label]
  msg := sprintf("Missing required label: %s", [label])
}

# --- Rule 5: Deny use of 'latest' image tag
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container '%s' uses 'latest' tag, which is not allowed", [container.name])
}

# --- Rule 6: Deny adding Linux capabilities
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.capabilities.add[_]
  msg := sprintf("Container '%s' adds Linux capabilities, which is not allowed", [container.name])
}

# --- Rule 7: Deny hostNetwork usage
deny[msg] {
  input.kind == "Pod"
  input.spec.hostNetwork == true
  msg := "Use of hostNetwork is forbidden"
}
package k8s.block_terminal_access

deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.operation == "CONNECT"
  subresource := input.request.requestSubResource
  subresource == "exec" or subresource == "attach"

  msg := sprintf("Terminal access to Pod '%s/%s' via '%s' is not allowed.",
    [input.request.namespace, input.request.name, subresource])
}