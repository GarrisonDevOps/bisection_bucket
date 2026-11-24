# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Returns a hash of { agent_reference => count_of_organizations_with_agent_effectively_enabled }.
        #
        # Effective enablement means either:
        # - An explicit Ai::OrganizationFoundationalAgentStatus record with enabled: true, OR
        # - No explicit record AND the instance-level foundational_agents_default_enabled is true.
        #
        # New agents defined in Ai::FoundationalChatAgent are automatically included.
        # The `chat` agent is always enabled and excluded from counting.
        class FoundationalAgentEnabledCountsMetric < GenericMetric
          value do
            # Service Ping is instance-scoped: read the legacy instance-wide
            # settings row, which belongs to the default organization.
            default_organization = ::Organizations::Organization.default_organization # rubocop:disable Gitlab/AvoidDefaultOrganization -- Service Ping reports instance-level values
            instance_default =
              default_organization &&
              ::Ai::Setting.for_organization_read_only(default_organization).foundational_agents_default_enabled
            total = ::Organizations::Organization.count

            counts_by_reference = ::Ai::OrganizationFoundationalAgentStatus
              .group(:reference)
              .select(:reference,
                'COUNT(*) AS total_count',
                'COUNT(*) FILTER (WHERE enabled) AS enabled_count')
              .each_with_object({}) do |row, h|
                h[row.reference] = { total: row.total_count.to_i, enabled: row.enabled_count.to_i }
              end

            ::Ai::FoundationalChatAgent.all
              .reject(&:duo_chat?)
              .each_with_object({}) do |agent, result|
                counts = counts_by_reference[agent.reference] || { total: 0, enabled: 0 }
                inheriting_enabled = instance_default ? (total - counts[:total]) : 0

                result[agent.reference] = counts[:enabled] + inheriting_enabled
              end
          end
        end
      end
    end
  end
end
