# frozen_string_literal: true

module Ai
  module AmazonQ
    # Brings a group's Amazon Q integration row in line with the group's saved Duo availability.
    class SyncGroupIntegrationService
      # @param group [Group]
      def initialize(group)
        @group = group
      end

      # @return [ServiceResponse]
      def execute
        return ServiceResponse.success(message: 'Amazon Q is not connected') unless ::Ai::AmazonQ.connected?

        integration = group.amazon_q_integration
        return ServiceResponse.success(message: 'No Amazon Q integration') unless integration

        changes = integration_changes(integration)
        return ServiceResponse.success(message: 'Already in sync') if changes.empty?

        unless integration.update(changes)
          return ServiceResponse.error(message: integration.errors.full_messages.join(', '))
        end

        PropagateIntegrationWorker.perform_async(integration.id)

        ServiceResponse.success(payload: { integration: integration })
      end

      private

      attr_reader :group

      # The row keeps whatever it last synced to, so the saved namespace availability is the source of truth.
      # Amazon Q has no 'always_on'. Encrypted properties re-encrypt on every save, so only differing values
      # are assigned.
      #
      # @param integration [Integrations::AmazonQ]
      # @return [Hash]
      def integration_changes(integration)
        duo_availability = group.duo_availability.to_s
        availability = duo_availability == 'always_on' ? 'default_on' : duo_availability

        changes = {}
        changes[:availability] = availability if integration.availability != availability
        changes[:auto_review_enabled] = false if availability != 'default_on' && integration.auto_review_enabled
        changes
      end
    end
  end
end
