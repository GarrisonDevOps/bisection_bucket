# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes
    class ApprovalScanResultPolicyType < BaseObject
      graphql_name 'ApprovalScanResultPolicy'
      description 'Represents the scan result policy'

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Represents the name of the policy.'

      field :approvals_required,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Represents the required approvals defined in the policy.'

      field :report_type,
        type: ::Types::SecurityOrchestration::ApprovalReportTypeEnum,
        null: false,
        description: 'Represents the report_type of the approval rule.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
