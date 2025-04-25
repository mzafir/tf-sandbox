package saas.features
package api.ratelimit
package business.policy
package gateway.authz
package mesh.authz
package logging.audit

default allow = false

allow {
  input.user.tier == "pro"
  input.feature == "export_data"
}
default allow = false

allow {
  input.user.usage_count < data.limits[input.user.tier]
}

allow {
  input.user.region == "US"
  input.transaction.amount < 5000
}
allow {
  input.path == "/v1/users"
  input.method == "GET"
  input.token.scope[_] == "read:users"
}

allow {
  input.source.service == "frontend"
  input.destination.service == "backend"
  input.source.identity == "spiffe://example.org/frontend"
}


log_entry := {
  "user": input.user.id,
  "action": input.action,
  "resource": input.resource.id,
  "timestamp": input.timestamp
}