# frozen_string_literal: true

module GitlabSubscriptions
  module Duo
    class EnableCodeReviewFlowService
      include Gitlab::Utils::StrongMemoize

      def initialize(namespace:)
        @namespace = namespace
        @namespace_settings = namespace.namespace_settings
      end

      def execute
        return cannot_enable_code_review_error unless namespace_eligible?

        if should_enable_code_review_flow?
          seed_foundational_flows
          enable_code_review_flow
        else
          ServiceResponse.success
        end
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, namespace_id: namespace.id)
        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :namespace, :namespace_settings

      def cannot_enable_code_review_error
        ServiceResponse.error(
          message: s_('GitlabSubscriptions|Cannot enable the Code Review flow for this namespace'),
          reason: :cannot_enable_code_review_error
        )
      end

      def namespace_eligible?
        namespace.root? &&
          namespace.duo_features_enabled &&
          namespace.duo_agent_platform_enabled &&
          namespace.duo_foundational_flows_enabled &&
          actor.present?
      end

      def actor
        namespace.owners.find { |owner| owner.human? && owner.active? }
      end
      strong_memoize_attr :actor

      def should_enable_code_review_flow?
        namespace_settings.enable_duo_code_review_by_default_pending?
      end

      def enable_code_review_flow
        return code_review_flow_not_provisioned_error unless provision_code_review_flow

        ::Ai::CascadeDuoSettingsService.new(settings_payload, current_user: actor).cascade_for_group(namespace)

        namespace_settings.enable_duo_code_review_by_default_enabled!

        ServiceResponse.success
      rescue ActiveRecord::RecordInvalid => e
        ::Gitlab::ErrorTracking.track_exception(e, namespace_id: namespace.id)
        ServiceResponse.error(message: e.message)
      end

      def provision_code_review_flow
        previous_flow_ids = namespace.enabled_flow_catalog_item_ids
        namespace.sync_enabled_foundational_flows!(code_review_flow_ids)

        result = ::Ai::Catalog::Flows::SyncFoundationalFlowsService.new(namespace, current_user: actor).execute
        return true if result.payload[:failures].empty?

        namespace.sync_enabled_foundational_flows!(previous_flow_ids)
        false
      rescue StandardError
        namespace.sync_enabled_foundational_flows!(previous_flow_ids) if previous_flow_ids
        raise
      end

      def code_review_flow_ids
        ::Ai::Catalog::Item.foundational_flow_ids_for_references([code_review_flow_reference]).values
      end

      def code_review_flow_reference
        ::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference
      end

      def code_review_flow_not_provisioned_error
        ServiceResponse.error(
          message: 'Code Review flow was not provisioned',
          reason: :code_review_flow_not_provisioned
        )
      end

      def seed_foundational_flows
        Ai::Catalog::Flows::SeedFoundationalFlowsService.new.execute
      end

      def settings_payload
        {
          auto_duo_code_review_enabled: true,
          enabled_foundational_flows: [code_review_flow_reference]
        }
      end
    end
  end
end
