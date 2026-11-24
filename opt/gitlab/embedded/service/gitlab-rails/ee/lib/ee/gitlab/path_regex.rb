# frozen_string_literal: true

module EE
  module Gitlab
    module PathRegex
      extend ActiveSupport::Concern

      # OCI (Open Container Initiative) regexes for Container Virtual Registry
      # https://github.com/opencontainers/distribution-spec/blob/main/spec.md
      OCI_TAG_REGEX = /[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}/
      OCI_DIGEST_REGEX = /sha256:[a-f0-9]{64}/

      # https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-manifests
      OCI_TAG_OR_DIGEST_REGEX = /(?:#{OCI_TAG_REGEX.source}|#{OCI_DIGEST_REGEX.source})/

      # https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-blobs
      # Accepts various digest formats:
      # - sha256 with any length: sha256:[hex chars]
      # - Other algorithms: md5:..., sha512:..., etc.
      OCI_BLOB_DIGEST_REGEX = /(?:sha256:[a-f0-9]+|[a-zA-Z0-9][a-zA-Z0-9+.-]*:[a-zA-Z0-9]+)/

      class_methods do
        # Only a prefix when a segment follows: /o/:organization_path alone is the Organization's own page.
        def organization_scope_prefix_regex
          @organization_scope_prefix_regex ||= begin
            scope = ::Gitlab::PathRegex::ORGANIZATION_ROUTE_SCOPE

            %r{(?:/#{scope}/#{::Gitlab::PathRegex.organization_route_regex}(?=/))?}
          end
        end

        def saml_callback_regex
          @saml_callback_regex ||= %r{\A\/groups\/(?<group>#{full_namespace_route_regex})\/\-\/saml\/callback\z}
        end

        def sign_in_flow_route_regex
          @sign_in_flow_route_regex ||= sign_in_flow_route_regex_for(::Gitlab::Auth::OAuth::Provider.providers)
        end

        # Public only so specs can pass a fixed provider list; everything else uses sign_in_flow_route_regex.
        # SAML is top-level only (SamlProvider validates top_level_group); /users/auth/:name is also a user profile.
        def sign_in_flow_route_regex_for(providers)
          provider_names = Regexp.union(providers.map(&:to_s))

          %r{\A(?:
            (?:/o/[^/]+)?/(?:
              users/sign_in
              |users/sign_in_path
              |users/passkeys/sign_in
              |users/resend_verification_code
              |users/fallback_to_email_otp
              |users/skip_verification_for_now
              |users/skip_verification_confirmation
              |users/successful_verification
              |oauth/authorize
            )
            |/groups/#{::Gitlab::PathRegex::NAMESPACE_FORMAT_REGEX}/-/saml/(?:sso|callback)
            |/users/auth/#{provider_names}(?:/callback)?
          )\z}x
        end

        # Git LFS paths are under .git, so the Git HTTP regex covers them too.
        def git_or_dependency_proxy_route_regex
          @git_or_dependency_proxy_route_regex ||=
            /#{repository_git_http_route_regex}|#{dependency_proxy_containers_route_regex}/
        end

        # Past the top level, `-`, raw, blob, tree and blame may appear only as `-/` or `-/wikis/` before uploads/, so
        # repository pages ending in uploads/<x>/<y>, including the unscoped deprecated routes, stay pages.
        def upload_or_pwa_manifest_route_regex
          @upload_or_pwa_manifest_route_regex ||= %r{
            \A(?:/o/[^/]+)?(?:
              /-/(?:project|group)/[^/]+/uploads/[^/]+/[^/]+
              |(?!/api/)/(?!-/)[^/]+(?:/(?!(?:-|raw|blob|tree|blame)/)[^/]+)+
                /(?:-/(?:wikis/)?)?uploads/(?!(?:-|raw|blob|tree|blame)/)[^/]+/[^/]+
              |/uploads/-/system/.+
              |/-/manifest\.json
            )\z
          }x
        end

        def oauth_token_grant_route_regex
          @oauth_token_grant_route_regex ||= %r{\A(?:/o/[^/]+)?/oauth/(?:token|authorize_device)(?:\.json)?\z}
        end

        def oauth_dynamic_registration_route_regex
          @oauth_dynamic_registration_route_regex ||= %r{\A(?:/o/[^/]+)?/oauth/register(?:\.json)?\z}
        end

        def discovery_document_route_regex
          @discovery_document_route_regex ||= %r{
            \A/(?:
              \.well-known/(?:
                (?:openid-configuration|oauth-authorization-server|oauth-protected-resource)(?:/api/v4/(?:orbit/)?mcp)?
                |terraform\.json
              )
              |oauth/discovery/keys
            )\z
          }x
        end

        def oci_tag_regex
          @oci_tag_regex ||= OCI_TAG_REGEX
        end

        def oci_digest_regex
          @oci_digest_regex ||= OCI_DIGEST_REGEX
        end

        def oci_tag_or_digest_regex
          @oci_tag_or_digest_regex ||= OCI_TAG_OR_DIGEST_REGEX
        end

        def oci_blob_digest_regex
          @oci_blob_digest_regex ||= OCI_BLOB_DIGEST_REGEX
        end

        def pipeline_trigger_api_route_regex
          @pipeline_trigger_api_route_regex ||= %r{\A/api/v4/projects/[^/]+/(?:ref/.+/)?trigger/pipeline(?:\.json)?\z}
        end

        def runner_registration_api_route_regex
          @runner_registration_api_route_regex ||= %r{\A/api/v4/runners(?:\.json)?\z}
        end

        def unleash_api_route_regex
          @unleash_api_route_regex ||= %r{\A/api/v4/feature_flags/unleash/}
        end

        # Remove with the deprecated tools: https://gitlab.com/gitlab-com/gl-infra/production-engineering/-/work_items/30052
        def deprecated_secure_files_installer_route_regex
          @deprecated_secure_files_installer_route_regex ||= %r{
            \A/gitlab-org/incubation-engineering/mobile-devops/(?:download|load)-secure-files/-/(?:
              raw/main/installer |
              releases/(?:permalink/latest|[^/]+)/downloads/[^/]+ |
              jobs/(?:artifacts/main|\d+/artifacts)/raw/(?:dist|releases)/[^/]+
            )\z
          }x
        end

        def group_scim_api_route_regex
          @group_scim_api_route_regex ||= %r{\A/api/scim/v2/groups/[^/]+/Users(?:[/.]|\z)}
        end

        # Only the development tool routes Atlassian's servers call. Lifecycle events stay counted because verifying
        # them fetches a public key over the network. The app descriptor and public keys are fetched once per install,
        # and the other routes are browser requests that count against users' own IPs, except the redirect below.
        def jira_connect_atlassian_route_regex
          @jira_connect_atlassian_route_regex ||=
            %r{\A(?:/o/[^/]+)?/-/jira_connect/(?:workspaces/search|repositories/(?:search|associate))(?:\.json)?\z}
        end

        # Jira's create-branch link sends the user's browser here, and GitLab.com redirects a Marketplace install that
        # points at a Self-Managed or Dedicated instance onward, so one office IP with no GitLab.com session would share
        # one anonymous budget. The JWT check is a local HMAC verify plus one indexed lookup, so a bad token is cheap.
        def jira_connect_branch_route_regex
          @jira_connect_branch_route_regex ||= %r{\A(?:/o/[^/]+)?/-/jira_connect/branches/route\z}
        end

        def slack_app_api_route_regex
          @slack_app_api_route_regex ||= %r{\A/api/v4/(?:slack/trigger(?:\.json)?\z|integrations/slack/)}
        end

        # Anchored, unlike ALERTS_NOTIFY_PATH_REGEX, so a file page ending in alerts/notify still counts. Past the top
        # level it rejects every reserved project word, which no subgroup or project can be named, and needs a project.
        def alert_notification_route_regex
          @alert_notification_route_regex ||= begin
            reserved = Regexp.union(::Gitlab::PathRegex::ILLEGAL_GROUP_PATH_WORDS)

            %r{
              \A(?!/api/)/(?!-/)[^/]+(?:/(?!#{reserved}/)[^/]+)+
              /(?:prometheus/)?alerts/notify(?:/[^/]+/[A-Za-z0-9]+)?(?:\.json)?\z
            }x
          end
        end

        def mailgun_webhook_route_regex
          @mailgun_webhook_route_regex ||= %r{\A/-/(?:mailgun/webhooks|members/mailgun/permanent_failures)(?:\.json)?\z}
        end

        # Anonymous / redirects to about.gitlab.com. The IP's budget, drained by issue pages
        # (/api/graphql has no target namespace), must not stop visitors from getting there.
        # /o/:organization_path is the Organization's own page, so it stays counted.
        def home_page_route_regex
          @home_page_route_regex ||= %r{\A/?\z}
        end

        # Anonymous sign-up steps: the form, the checks while typing, and identity verification.
        # The username uses the browser's pattern, which allows .git and .atom endings, so every check the form sends
        # is covered. The identity verification actions are those in ee/config/routes/identity_verification.rb.
        # The two subscriptions actions load and check the credit card form during identity verification.
        def sign_up_flow_route_regex
          @sign_up_flow_route_regex ||= begin
            # A Regexp keeps its own flags, so x mode can't strip a space or # from the username pattern.
            username = Regexp.new(::Gitlab::PathRegex::NAMESPACE_FORMAT_REGEX_JS)

            %r{\A#{organization_scope_prefix_regex}(?:
              /users
              |/users/sign_up
              |/users/password/complexity
              |/users/#{username}/exists
              |/users/identity_verification(?:/(?:
                verification_state
                |verify_email_code|resend_email_code
                |send_phone_verification_code|verify_phone_verification_code
                |arkose_labs_challenge|verify_arkose_labs_session
                |toggle_phone_exemption
                |verify_credit_card|verify_credit_card_captcha
                |success|restricted
              ))?
              |/users/almost_there
              |/-/subscriptions/(?:payment_form|validate_payment_method)
              |/-/invites/[A-Za-z0-9_-]+
              |/-/arkose/data_exchange_payload
            )(?:\.json)?\z}x
          end
        end

        # All methods are excluded, including the POSTs that send password reset, confirmation, and unlock emails.
        def account_recovery_route_regex
          @account_recovery_route_regex ||= %r{\A#{organization_scope_prefix_regex}/users/(?:
            password(?:/(?:new|edit))?
            |(?:confirmation|unlock)(?:/new)?
          )\z}x
        end

        # The trial form and its submit forms in the trial-account workflow
        def trial_registration_route_regex
          @trial_registration_route_regex ||=
            %r{\A#{organization_scope_prefix_regex}/-/trial_registrations(?:/new)?\z}
        end

        # Stopgap for the gprd HAProxy api check. Remove once it uses /-/readiness, which is already exempt.
        # https://gitlab.com/gitlab-com/gl-infra/production-engineering/-/work_items/30022
        def haproxy_api_health_check_route_regex
          @haproxy_api_health_check_route_regex ||= %r{\A/-/k8s/api/-/readiness\z}
        end

        def usage_data_telemetry_api_route_regex
          @usage_data_telemetry_api_route_regex ||=
            %r{\A/api/v4/usage_data/(?:track_events?|increment_counter|increment_unique_users)(?:\.json)?\z}
        end

        # No /api/ prefix and no `-` segment, so an API or /-/raw/ URL ending in the same suffix still counts.
        def git_operation_continuation_route_regex
          @git_operation_continuation_route_regex ||= %r{
            \A(?!/api/)(?:/(?!-/)[^/]+)+\.git/
            (?:git-(?:upload|receive)-pack\z|gitlab-lfs/objects/[0-9a-f]{64}(?:/|\z))
          }x
        end
      end
    end
  end
end
