# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyViolationInfoType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyViolationInfo'
      description 'Represents generic policy violation information.'

      include ::Gitlab::Utils::StrongMemoize

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Represents the name of the violated policy.'

      field :report_type,
        type: ApprovalReportTypeEnum,
        null: false,
        description: 'Represents the report type.'

      field :status,
        type: PolicyViolationStatusEnum,
        description: 'Represents the status of the violated policy.'

      field :enforcement_type,
        type: PolicyEnforcementTypeEnum,
        null: false,
        description: 'Represents the enforcement type of the violated policy.'

      field :security_policy_id,
        type: GraphQL::Types::ID,
        description: 'Represents the violated security policy id.'

      field :dismissed,
        type: GraphQL::Types::Boolean,
        null: false,
        description: 'Represents if a warn mode policy violation was dismissed.'
    end
  end
end
