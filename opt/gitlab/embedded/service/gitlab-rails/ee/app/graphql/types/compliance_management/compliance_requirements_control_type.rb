# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- ComplianceRequirementsControlType is accessible from authenticated resolvers only

module Types
  module ComplianceManagement
    class ComplianceRequirementsControlType < Types::BaseObject
      graphql_name 'ComplianceRequirementsControl'
      description 'Represents a ComplianceRequirementsControl associated with a ComplianceRequirement'

      field :id, GraphQL::Types::ID,
        null: false,
        description: 'Compliance requirements control ID.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the compliance control.'

      field :expression, GraphQL::Types::String,
        null: true,
        description: 'Expression of the compliance control.'

      field :control_type, GraphQL::Types::String,
        null: false,
        description: 'Type of the compliance control.'

      field :external_control_name, GraphQL::Types::String,
        null: true,
        description: 'Name of the external control.'

      field :external_url, GraphQL::Types::String, # rubocop: disable GraphQL/ExtractType -- maintain fields on this level for backwards compatibility
        null: true,
        description: 'URL of the external control.'

      field :ping_enabled, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether ping is enabled for external controls.'

      field :compliance_requirement, ::Types::ComplianceManagement::ComplianceRequirementType,
        null: true,
        description: 'Compliance requirement associated with the control.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
