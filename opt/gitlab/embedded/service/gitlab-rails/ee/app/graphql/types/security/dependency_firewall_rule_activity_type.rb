# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- authorization is handled on the group field and in the finder
    class DependencyFirewallRuleActivityType < BaseObject
      graphql_name 'DependencyFirewallRuleActivity'
      description 'Block and warn enforcement activity for a single dependency firewall policy rule.'
      authorize_granular_token parent_authorizes: :read_security_policy

      field :activity_count, GraphQL::Types::Int, null: false,
        description: 'Activity count matching the rule mode: blocks for enforce, warns for warn.'
      field :blocked_count, GraphQL::Types::Int, null: false,
        description: 'Number of blocked enforcement events for the rule in the window.'
      field :enabled, GraphQL::Types::Boolean, null: false,
        description: 'Whether the policy the rule belongs to is enabled.'
      field :id, ::Types::GlobalIDType[::Security::DependencyFirewallPolicyRule], null: false,
        description: 'Global ID of the dependency firewall policy rule.'
      field :last_modified, ::Types::Security::DependencyFirewallRuleLastModifiedType, null: true,
        description: 'When and by whom the policy the rule belongs to was last modified.'
      field :mode, ::Types::SecurityOrchestration::PolicyEnforcementTypeEnum, null: true,
        description: 'Enforcement mode of the rule.'
      field :package_version_entries, [::Types::Security::DependencyFirewallPackageVersionEntryType], null: true,
        experiment: { milestone: '19.6' },
        description: 'Package versions denied by the rule. Returns `null` unless the rule is a `package_version` ' \
          'rule and the `dependency_firewall_access` and `dependency_firewall_package_version` feature flags ' \
          'are enabled.'
      field :policy_name, GraphQL::Types::String, null: true,
        description: 'Name of the policy the rule belongs to.'
      field :rule_type, ::Types::Security::DependencyFirewallRuleTypeEnum, null: true,
        description: 'Type of the rule.'
      field :scope, ::Types::SecurityOrchestration::PolicyScopeType, null: true,
        description: 'Scope of the policy the rule belongs to.'
      field :source, ::Types::SecurityOrchestration::SecurityPolicySourceType, null: true,
        description: 'Source of the policy, indicating whether it is inherited from an ancestor group.'
      field :source_relationship, ::Types::SecurityOrchestration::SecurityPolicyRelationTypeEnum, null: true,
        description: 'Where the policy is defined relative to the viewed container.'
      field :warned_count, GraphQL::Types::Int, null: false,
        description: 'Number of warned enforcement events for the rule in the window.'

      def id
        object.rule.to_global_id
      end

      def last_modified
        { at: object.last_modified_at, by: object.last_modified_by }
      end

      def rule_type
        object.rule.type
      end

      def package_version_entries
        return unless object.rule.type_package_version?
        return unless ::Security::DependencyFirewall::Availability.package_version_rules_enabled?(object.container)

        Array(object.rule.typed_content['denied']).map do |entry|
          {
            name: entry['name'],
            version: entry['version'],
            reason: entry['reason'],
            reference_link: entry['reference_link']
          }
        end
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
