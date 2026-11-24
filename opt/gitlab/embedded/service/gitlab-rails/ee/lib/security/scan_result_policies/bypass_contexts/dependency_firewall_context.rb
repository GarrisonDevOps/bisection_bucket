# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module BypassContexts
      class DependencyFirewallContext < BaseContext
        def initialize(purl:, operation:, session_id: nil)
          @purl = purl
          @operation = operation
          @session_id = session_id
        end

        def audit_name(bypass_type)
          "dependency_firewall_#{bypass_type}_bypass"
        end

        def audit_message(bypass_type:, identifier:, project:, security_policy:, **_kwargs)
          <<~MSG.squish
            Dependency firewall policy '#{security_policy.name}' for project '#{project.full_path}'
            has been bypassed by #{bypass_type} with ID: #{identifier} for #{operation} of #{purl}
          MSG
        end

        def enrich_audit_details(details, **_kwargs)
          enriched = details.merge(purl: purl, operation: operation)
          enriched[:session_id] = session_id if session_id

          enriched
        end

        private

        attr_reader :purl, :operation, :session_id
      end
    end
  end
end
