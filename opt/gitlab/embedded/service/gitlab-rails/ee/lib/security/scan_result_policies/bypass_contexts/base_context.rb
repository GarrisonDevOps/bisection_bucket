# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module BypassContexts
      class BaseContext
        def initialize(push_options: nil)
          @push_options = push_options
        end

        def suppress_reason_required_error?
          false
        end

        def audit_name(_bypass_type)
          raise NotImplementedError
        end

        def audit_message(bypass_type:, identifier:, branch_name:, project:, user:, security_policy:)
          raise NotImplementedError
        end

        def enrich_audit_details(details, **_kwargs)
          details
        end

        def include_bypass_reason_in_details?
          false
        end

        def bypass_reason
          return if push_options.nil?

          reason = push_options.get(:security_policy)&.dig(:bypass_reason)
          Sanitize.clean(reason).presence if reason.present?
        end

        private

        attr_reader :push_options
      end
    end
  end
end
