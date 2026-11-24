# frozen_string_literal: true

module Types
  module Security
    module Ascp
      class SecurityGuidelineInputType < BaseInputObject
        graphql_name 'AscpSecurityGuidelineInput'
        description 'Input type for creating a security guideline'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Policy name.'

        argument :operation, GraphQL::Types::String,
          required: true,
          description: 'Security-sensitive operation.'

        argument :legitimate_use, GraphQL::Types::String,
          required: false,
          description: 'When the operation is expected and acceptable.'

        argument :security_boundary, GraphQL::Types::String,
          required: false,
          description: 'When the operation becomes a security risk.'

        argument :business_context, GraphQL::Types::String,
          required: false,
          description: 'How to assess business impact if violated.'

        argument :severity_if_violated, Types::Security::Ascp::SeverityEnum,
          required: false,
          default_value: 'medium',
          description: 'Severity level if the guideline is violated.'
      end
    end
  end
end
