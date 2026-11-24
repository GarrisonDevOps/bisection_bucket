# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module BypassContexts
      class MergeRequestContext < BaseContext
        def initialize(merge_request:, reason:)
          @merge_request = merge_request
          @reason = reason
        end

        def audit_name(_bypass_type)
          'security_policy_merge_request_bypass'
        end

        def audit_message(project:, user:, security_policy:, bypass_type: nil, **_kwargs)
          actor_description = bot_actor_description(user, bypass_type) || user.name

          <<~MSG.squish
            Security policy #{security_policy.name} in merge request
            (#{project.full_path}!#{merge_request.iid}) has been bypassed by #{actor_description}
          MSG
        end

        def enrich_audit_details(details, **_kwargs)
          base = {
            merge_request_id: merge_request.id,
            merge_request_iid: merge_request.iid,
            reason: reason
          }

          base[:bypass_type] = :merge_request unless details.key?(:bypass_type)

          base.merge(details)
        end

        def bypass_reason
          reason
        end

        private

        attr_reader :merge_request, :reason

        def bot_actor_description(user, bypass_type)
          case bypass_type
          when :access_token
            "access token #{user.name}"
          when :service_account
            "service account #{user.name}"
          end
        end
      end
    end
  end
end
