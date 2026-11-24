# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class UpdateExperimentsService
      def initialize(policy_configuration:)
        @policy_configuration = policy_configuration
      end

      def execute
        policy_configuration.update!(experiments: extracted_experiments_from_policy)
      end

      private

      attr_reader :policy_configuration

      delegate :policy_hash, to: :policy_configuration, allow_nil: true

      def extracted_experiments_from_policy
        return {} if policy_hash.blank?

        policy_hash[:experiments] || {}
      end
    end
  end
end
