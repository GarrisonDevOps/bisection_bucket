# frozen_string_literal: true

module Types
  module ComplianceManagement
    class ComplianceRequirementsControlInputType < BaseInputObject
      graphql_name 'ComplianceRequirementsControlInput'

      argument :name,
        GraphQL::Types::String,
        required: true,
        description: 'New name for the compliance requirement control.'

      argument :expression,
        GraphQL::Types::String,
        required: false,
        description: 'Expression of the compliance control. Derived from the name of the control ' \
          'when omitted for an internal control.'

      argument :control_type,
        GraphQL::Types::String,
        required: false,
        description: 'Type of the compliance control.'

      argument :external_control_name,
        GraphQL::Types::String,
        required: false,
        description: 'Name of the external control.'

      argument :external_url,
        GraphQL::Types::String,
        required: false,
        description: 'URL of the external control.'

      argument :secret_token,
        GraphQL::Types::String,
        required: false,
        description: 'Secret token for an external control.'

      argument :ping_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Whether ping is enabled for external controls.'
    end
  end
end
