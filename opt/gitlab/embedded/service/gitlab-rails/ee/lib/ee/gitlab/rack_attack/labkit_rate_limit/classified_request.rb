# frozen_string_literal: true

module EE
  module Gitlab
    module RackAttack
      module LabkitRateLimit
        module ClassifiedRequest
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          private

          # Strings and ids stay uncoerced, so they live with the identity facts.
          override :identity_facts
          def identity_facts
            return super unless flag_policy.gitlab_com?

            super.merge(
              requester_plan: requester_plan,
              target_namespace_plan: target_namespace_plan,
              target_root_namespace_id: target_root_namespace_id,
              expired_oauth_token_id: expired_oauth_token_id
            )
          end

          # Extends the classification facts (not labkit_facts) so the strict-boolean
          # coercion in Gitlab::RackAttack::LabkitRateLimit::ClassifiedRequest#labkit_facts
          # applies to these facts too.
          override :classification_facts
          def classification_facts
            super.merge(
              setting_incident_management_notification:
                ::Gitlab::Throttle.settings.throttle_incident_management_notification_enabled,
              verified_geo_request: verified_geo_request? || geo_proxy_workhorse_request?,
              unauthenticated_limits_active: flag_policy.unauthenticated_info_enabled?,
              unauthenticated_enforced: flag_policy.unauthenticated_enforce_enabled?,
              # The per-IP rules skip the request only once the expired token rules enforce, so the
              # observe stage leaves the request under per-IP enforcement as before.
              expired_oauth_token_enforced:
                expired_oauth_token_id.present? && flag_policy.expired_oauth_token_per_token_enforced?,
              **flag_policy.plan_flags,
              **(mcp_path? ? flag_policy.mcp_plan_flags : {})
            )
          end

          def flag_policy
            ::Gitlab::RateLimit::FlagPolicy
          end

          # Every authenticated requester carries a plan. A deploy token resolves it
          # from the namespace it belongs to; a job token resolves it from the job's
          # user, which is already what requester holds. A runner token reaches none
          # of this: it sets runner_id and no requester, so the guard above returns.
          def requester_plan
            return unless requester[:id]

            if requester[:type] == 'deploy_token'
              ::Gitlab::RateLimit::TierResolver.namespace_tier_for(requester_root_namespace_id)
            else
              ::Gitlab::RateLimit::TierResolver.tier_for(requester[:type], requester[:id])
            end
          end
          strong_memoize_attr :requester_plan

          # The namespace the requester authenticated as, which is not necessarily the one
          # the request addresses: a deploy token belongs to one project or group, and a
          # job token can reach another namespace through the job-token allowlist. Only
          # requester_plan reads this.
          def requester_root_namespace_id
            return unless requester[:type] == 'deploy_token'

            token = authenticated_requester

            if token.project_id
              ::Gitlab::RateLimit::TargetNamespace.id_for_project(token.project_id)
            else
              ::Gitlab::RateLimit::TargetNamespace.id_for_group(token.group_id)
            end
          end
          strong_memoize_attr :requester_root_namespace_id

          # Always the path, for every requester type, so the fact describes what the
          # request addresses rather than what it authenticated as. The raw path goes to
          # TargetNamespace, which strips the relative URL root itself.
          def target_root_namespace_id
            ::Gitlab::RateLimit::TargetNamespace.id_for_path(path)
          end
          strong_memoize_attr :target_root_namespace_id

          def target_namespace_plan
            return unless target_root_namespace_id

            ::Gitlab::RateLimit::TierResolver.namespace_tier_for(target_root_namespace_id)
          end
          strong_memoize_attr :target_namespace_plan

          # From the auth failure that resolving the requester records. Feed paths also check the token but
          # serve the page anonymously instead of the 401, so they stay on the per-IP rules.
          #
          # @return [String, nil]
          def expired_oauth_token_id
            return unless rejects_expired_token_path? && flag_policy.expired_oauth_token_per_token_enabled?
            # Also what records the auth failure read below, so it must run first.
            return if requester[:id]

            context = ::Gitlab::ApplicationContext
            return unless context.current_context_attribute(:auth_fail_reason) == 'token_expired'

            token_id = context.current_context_attribute(:auth_fail_token_id)
            token_id if token_id&.start_with?("#{::OauthAccessToken.name}/")
          end
          strong_memoize_attr :expired_oauth_token_id

          def rejects_expired_token_path?
            matches?(%r{\A/api/}) || oauth_token_check_path?
          end
        end
      end
    end
  end
end
