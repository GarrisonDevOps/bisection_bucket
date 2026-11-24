# frozen_string_literal: true

module Types
  module Security
    # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done on the parent field
    class TriageAndRemediationTriggerFlowStatusType < BaseObject
      graphql_name 'TriageAndRemediationTriggerFlowStatus'
      description 'AI flow status of a triage and remediation trigger type.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :trigger_type, Types::Security::ScanProfileTriggerTypeEnum,
        null: false,
        experiment: { milestone: '19.6' },
        description: 'Trigger type the flow status applies to.'

      field :flow_status, Types::Security::TriageAndRemediationFlowStatusEnum,
        null: false,
        experiment: { milestone: '19.6' },
        description: 'Whether the AI flow behind the trigger type is enabled, based on Duo configuration.'

      # rubocop:disable GraphQL/ExtractType -- This type already describes the trigger's flow, so it needs no nested flow type
      field :flow_name, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Display name of the foundational flow behind the trigger type, ' \
          'as GitLab Duo settings lists it. Null when the trigger type has no flow.'
      # rubocop:enable GraphQL/ExtractType
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
