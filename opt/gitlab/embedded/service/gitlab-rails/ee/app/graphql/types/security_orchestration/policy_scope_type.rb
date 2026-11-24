# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyScopeType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- This is a read from policy YAML
      graphql_name 'PolicyScope'

      authorize []

      field :match_mode, PolicyScopeMatchModeEnum,
        null: false,
        description: 'Specifies how multiple policy scope conditions are combined.',
        experiment: { milestone: '18.10' }

      field :compliance_frameworks, ::Types::ComplianceManagement::ComplianceFrameworkType.connection_type,
        null: false,
        description: 'Compliance Frameworks linked to the policy.'

      field :excluding_personal_projects, GraphQL::Types::Boolean,
        null: false,
        description: 'Boolean indicating whether personal projects are excluded from the policy.'

      field :excluding_archived_projects, GraphQL::Types::Boolean,
        null: false,
        description: 'Boolean indicating whether archived projects are excluded from the policy.'

      field :including_projects, ::Types::ProjectType.connection_type,
        null: false,
        description: 'Projects to which the policy should be applied.'

      field :excluding_projects, ::Types::ProjectType.connection_type,
        null: false,
        description: 'Projects to which the policy should not be applied.'

      field :including_groups, ::Types::GroupType.connection_type,
        null: false,
        description: 'Groups to which the policy should be applied.'

      field :excluding_groups, ::Types::GroupType.connection_type,
        null: false,
        description: 'Groups to which the policy should not be applied.'

      field :including_business_impact_attributes, ::Types::Security::AttributeType.connection_type,
        null: false,
        description: 'Business Impact security attributes that the policy applies to.',
        experiment: { milestone: '18.11' }

      field :excluding_business_impact_attributes, ::Types::Security::AttributeType.connection_type,
        null: false,
        description: 'Business Impact security attributes that the policy does not apply to.',
        experiment: { milestone: '18.11' }

      field :including_application_attributes, ::Types::Security::AttributeType.connection_type,
        null: false,
        description: 'Application security attributes that the policy applies to.',
        experiment: { milestone: '19.0' }

      field :excluding_application_attributes, ::Types::Security::AttributeType.connection_type,
        null: false,
        description: 'Application security attributes that the policy does not apply to.',
        experiment: { milestone: '19.0' }

      field :including_business_unit_attributes, ::Types::Security::AttributeType.connection_type, # rubocop:disable GraphQL/ExtractType -- following the convention in the GraphQL type
        null: false,
        description: 'Business Unit security attributes that the policy applies to.',
        experiment: { milestone: '19.1' }

      field :excluding_business_unit_attributes, ::Types::Security::AttributeType.connection_type, # rubocop:disable GraphQL/ExtractType -- following the convention in the GraphQL type
        null: false,
        description: 'Business Unit security attributes that the policy does not apply to.',
        experiment: { milestone: '19.1' }

      field :including_exposure_attributes, ::Types::Security::AttributeType.connection_type, # rubocop:disable GraphQL/ExtractType -- following the convention in the GraphQL type
        null: false,
        description: 'Exposure security attributes that the policy applies to.',
        experiment: { milestone: '19.1' }

      field :excluding_exposure_attributes, ::Types::Security::AttributeType.connection_type, # rubocop:disable GraphQL/ExtractType -- following the convention in the GraphQL type
        null: false,
        description: 'Exposure security attributes that the policy does not apply to.',
        experiment: { milestone: '19.1' }
    end
  end
end
