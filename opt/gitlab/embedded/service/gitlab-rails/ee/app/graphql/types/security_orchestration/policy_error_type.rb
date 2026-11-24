# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyErrorType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyError'
      description 'Represents an error that can occur during policy evaluation.'

      field :error,
        type: PolicyViolationErrorTypeEnum,
        null: false,
        description: 'Represents error code.'

      field :report_type,
        type: ApprovalReportTypeEnum,
        null: false,
        description: 'Represents the report type.'

      field :message,
        type: GraphQL::Types::String,
        null: false,
        description: 'Represents the error message.'

      field :data,
        type: GraphQL::Types::JSON,
        null: true,
        description: 'Represents the error-specific data.'
    end
  end
end
