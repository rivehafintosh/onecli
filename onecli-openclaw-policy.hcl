path "kv-admin/data/openclaw/*" {
  capabilities = ["create","read","update","list"]
}

path "kv-admin/metadata/openclaw/*" {
  capabilities = ["create","read","update","list"]
}

path "kv/data/onecli/*" {
  capabilities = ["create","read","update","list","delete"]
}

path "kv/metadata/onecli/*" {
  capabilities = ["create", "read", "update", "list", "delete"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
