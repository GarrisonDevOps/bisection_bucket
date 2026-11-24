# frozen_string_literal: true

module Types
  module Security
    # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done on the Project field
    class TriageAndRemediationCapabilityType < BaseObject
      graphql_name 'TriageAndRemediationCapability'
      description 'A triage and remediation capability and its coverage state for a project.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :trigger_type, Types::Security::ScanProfileTriggerTypeEnum,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Trigger type the capability applies to.'

      field :enabled, GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Indicates the capability is attached to the project.'

      field :run_mode, Types::Security::ScanProfiles::RunModeEnum,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Run mode for the capability.'

      field :flow_status, Types::Security::TriageAndRemediationFlowStatusEnum,
        null: false,
        experiment: { milestone: '19.6' },
        description: 'Whether the AI flow behind the capability is enabled, based on Duo configuration.'

      def trigger_type
        object[:trigger_type].to_s
      end

      def run_mode
        object[:run_mode]&.to_s
      end

      def flow_status
        object[:flow_status].to_s
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
