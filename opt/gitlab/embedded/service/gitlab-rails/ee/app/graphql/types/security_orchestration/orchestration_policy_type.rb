# frozen_string_literal: true

module Types
  module SecurityOrchestration
    module OrchestrationPolicyType
      module Scopes
        def authorization_scopes
          super + [:ai_workflows]
        end
      end

      include Types::BaseInterface

      def self.included(base_class)
        super

        base_class.extend(Scopes)
      end

      field :id, ::Types::GlobalIDType[::Security::Policy],
        null: true,
        experiment: { milestone: '18.11' },
        description: 'ID of the policy. Returns null if the policy has not been synced to the database yet.',
        scopes: [:api, :read_api, :ai_workflows]

      field :policy_configuration_id, ::Types::GlobalIDType[::Security::OrchestrationPolicyConfiguration],
        null: true,
        experiment: { milestone: '18.11' },
        description: 'ID of the policy configuration the policy belongs to.'

      field :description, GraphQL::Types::String, null: false, description: 'Description of the policy.'

      field :edit_path, GraphQL::Types::String, null: false, description: 'URL of policy edit page.'

      field :enabled, GraphQL::Types::Boolean, null: false, description: 'Indicates whether the policy is enabled.', scopes: [:api, :read_api, :ai_workflows]

      field :name, GraphQL::Types::String, null: false, description: 'Name of the policy.', scopes: [:api, :read_api, :ai_workflows]

      field :updated_at, Types::TimeType, null: false, calls_gitaly: true, description: 'Timestamp of when the policy YAML was last updated.'

      field :yaml, GraphQL::Types::String, null: false, description: 'YAML definition of the policy.', scopes: [:api, :read_api, :ai_workflows]

      field :policy_scope, ::Types::SecurityOrchestration::PolicyScopeType, null: true, description: 'Scope of the policy.'

      field :csp, ::GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether the policy comes from a centralized security policy group.',
        experiment: { milestone: '18.1' }

      def id
        return unless policy_record

        ::Gitlab::Graphql::Lazy.with_value(policy_record) { |record| record&.to_global_id }
      end

      def updated_at
        config = object[:config]
        return config&.policy_last_updated_at unless policy_record

        ::Gitlab::Graphql::Lazy.with_value(policy_record) do |record|
          record&.updated_at || config.policy_last_updated_at
        end
      end

      def policy_configuration_id
        object[:config]&.to_global_id
      end

      private

      def policy_record
        config = object[:config]
        policy_index = object[:policy_index]
        policy_type = object[:type]
        return unless config && !policy_index.nil? && policy_type

        BatchLoader::GraphQL.for([config.id, policy_type, policy_index]).batch do |keys, loader|
          load_policies_batch(keys, loader)
        end
      end

      def load_policies_batch(keys, loader)
        config_ids = keys.map(&:first).uniq
        ::Security::Policy.for_policy_configuration_ids(config_ids).undeleted.find_each do |policy|
          key = [policy.security_orchestration_policy_configuration_id, policy.type, policy.policy_index]
          loader.call(key, policy)
        end
      end
    end
  end
end
