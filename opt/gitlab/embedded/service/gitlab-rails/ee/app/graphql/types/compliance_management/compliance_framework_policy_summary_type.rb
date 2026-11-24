# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- accessible only via authenticated resolvers on ComplianceFrameworkType
module Types
  module ComplianceManagement
    class ComplianceFrameworkPolicySummaryType < Types::BaseObject
      graphql_name 'ComplianceFrameworkPolicySummary'
      description 'A security policy scoped to a compliance framework'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the security policy.'

      field :type, GraphQL::Types::String,
        null: true,
        description: 'Type of the security policy.'

      field :source, ::Types::SecurityOrchestration::SecurityPolicySourceType,
        null: true,
        description: 'Source of the security policy.'

      field :has_active_projects, GraphQL::Types::Boolean,
        null: false,
        resolver_method: :has_active_projects?,
        description: 'Whether the policy has at least one non-archived assigned project.'

      def has_active_projects?
        config = object[:config]
        policy_index = object[:policy_index]
        policy_type = object[:type]

        BatchLoader::GraphQL.for([config.id, policy_type, policy_index]).batch do |keys, loader|
          # keys is an array of [config_id, policy_type, policy_index] tuples
          config_ids = keys.map(&:first).uniq

          # Load all relevant policies with their projects in one query
          policies_with_active_projects = ::Security::PoliciesWithActiveProjectsFinder
            .new(config_ids: config_ids)
            .execute
            .to_set

          # For each key, check if a matching policy with active projects exists
          keys.each do |key|
            config_id, type, index = key
            has_active = policies_with_active_projects.include?([config_id, type, index])
            loader.call(key, has_active)
          end
        end
      end

      def type
        # scan_result_policy is the legacy name; normalize to approval_policy
        object[:type] == 'scan_result_policy' ? 'approval_policy' : object[:type]
      end
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
