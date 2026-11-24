# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsManagers
    module UserHelper
      extend ActiveSupport::Concern

      def user_auth_cel_program(group_id)
        # rubocop:disable Layout/LineLength -- CEL expression readability
        {
          variables: [
            { name: "base", expression: %("users") },
            { name: "uid", expression: %q(('user_id' in claims) ? string(claims['user_id']) : "") },
            { name: "mrid",
              expression: %q(('member_role_id' in claims && claims['member_role_id'] != null) ? string(claims['member_role_id']) : "") },
            { name: "rid", expression: %q(('role_id' in claims) ? string(claims['role_id']) : "") },
            { name: "expected_gid", expression: %("#{group_id}") },
            { name: "gid", expression: %q(('group_id' in claims) ? string(claims['group_id']) : "") },
            { name: "rgid", expression: %q(('root_group_id' in claims) ? string(claims['root_group_id']) : "") },
            { name: "orgid", expression: %q(('organization_id' in claims) ? string(claims['organization_id']) : "") },
            { name: "who", expression: %q(uid != "" ? "gitlab-user:" + uid : "gitlab-user:anonymous") },
            { name: "aud", expression: %q(('aud' in claims) ? claims['aud'] : "") },
            { name: "expected_aud", expression: %("#{aud}") },
            { name: "sub", expression: %q(('sub' in claims) ? claims['sub'] : "") },
            { name: "scope",
              expression: %q(('secrets_manager_scope' in claims) ? string(claims['secrets_manager_scope']) : "") },
            { name: "correlation_id",
              expression: %q(('correlation_id' in claims) ? string(claims['correlation_id']) : "") },
            # Token TTL (seconds) from an optional claim, defaulting to 5 minutes.
            # A missing, null, or non-positive claim falls back to the default. The
            # > 0 guard matters because OpenBao reads TTL 0 as "use the default",
            # which is its 32-day max. OpenBao caps the upper bound itself, so we
            # do not clamp it here. Reading it from a claim lets us tune the
            # lifetime from Rails later without re-provisioning the role.
            { name: "ttl_seconds",
              expression: %q(('secrets_manager_token_ttl' in claims && claims['secrets_manager_token_ttl'] != null && int(claims['secrets_manager_token_ttl']) > 0) ? int(claims['secrets_manager_token_ttl']) : 300) },
            { name: "ttl_ns", expression: %q(ttl_seconds * 1000000000) }
          ],
          expression: <<~'CEL'.strip
          sub == "" ? "missing subject" :
          !sub.startsWith("user:") ? "invalid subject for user authentication" :
          scope == "" ? "missing secrets_manager_scope" :
          scope != "user" ? "invalid secrets_manager_scope" :
          gid == "" ? "missing group_id" :
          gid != expected_gid ? "token group_id does not match group" :
          aud == "" ? "missing audience" :
          aud != expected_aud ? "audience validation failed" :
          uid == "" ? "missing user_id" :
          pb.Auth{
            display_name: who,
            alias: logical.Alias { name: who },
            lease_options: pb.LeaseOptions{TTL: ttl_ns, MaxTTL: ttl_ns, issue_time: now},
            policies:
              (uid  != "" ? [base + "/direct/user_"        + uid]  : []) +
              (mrid != "" ? [base + "/direct/member_role_" + mrid] : []) +
              (rid  != "" ? [base + "/roles/"              + rid]  : []),
            metadata: {
              "correlation_id": correlation_id,
              "group_id": gid,
              "root_group_id": rgid,
              "organization_id": orgid,
              "user_id": uid
            }
          }
          CEL
        }
        # rubocop:enable Layout/LineLength
      end
    end
  end
end
