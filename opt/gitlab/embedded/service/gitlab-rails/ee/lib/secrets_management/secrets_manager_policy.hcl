path "sys/namespaces/+"                     { capabilities = ["create", "update", "delete"] }
path "sys/rotate/recovery/init"             { capabilities = ["create", "update", "delete"] }

# read only, so this token cannot write its own policy directly
path "sys/policies/acl/secrets_manager"     { capabilities = ["read"] }

# with the recovery key, an admin can mint a root token to change this policy
path "sys/generate-root-token/attempt"      { capabilities = ["read", "update", "delete"] }
path "sys/generate-root-token/update"       { capabilities = ["update"] }

path "+/sys/namespaces/+"                   { capabilities = ["create", "update", "delete"] }

path "+/+/sys/namespaces/+"                 { capabilities = ["create", "update", "delete"] }

path "+/+/+/sys/mounts/secrets/kv"          { capabilities = ["create", "update"] }
path "+/+/+/sys/auth/+"                     { capabilities = ["create", "update", "sudo"] }
path "+/+/+/auth/+/config"                  { capabilities = ["create", "update"] }
path "+/+/+/auth/+/cel/role/+"              { capabilities = ["create", "update"] }
path "+/+/+/sys/policies/acl/*"             { capabilities = ["create", "update", "read", "delete"] }
path "+/+/+/sys/policies/detailed/acl*"     { capabilities = ["list"] }
path "+/+/+/secrets/kv/metadata/*"          { capabilities = ["create", "update", "read", "list"] }
path "+/+/+/secrets/kv/detailed-metadata/*" { capabilities = ["list"] }

# the +/+/+/ rules above also match some root namespace paths, these outrank them there,
# so a secrets engine mounted in the root namespace has to live under secrets/
path "sys/*"                                { capabilities = ["deny"] }
path "identity/*"                           { capabilities = ["deny"] }
path "secrets/*"                            { capabilities = ["deny"] }
path "auth/*"                               { capabilities = ["deny"] }
