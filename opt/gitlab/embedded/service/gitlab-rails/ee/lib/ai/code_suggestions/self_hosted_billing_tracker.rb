# frozen_string_literal: true

module Ai
  module CodeSuggestions
    # Sends a self-hosted DAP billing event to the cloud Duo Workflow Service for
    # each code suggestions request made on a self-hosted instance.
    #
    # Mirrors the TrackLlmCallForSelfHosted path that workhorse handles for Duo
    # Workflow, but called directly from Rails for the stateless completions endpoint.
    #
    # Returns a ServiceResponse. When billing is not applicable (cloud instance,
    # feature flag off, etc.) returns a success response so callers can treat it
    # as a no-op without special-casing.
    class SelfHostedBillingTracker
      FEATURE_QUALIFIED_NAME = "code_suggestions"

      def initialize(current_user:, feature_setting:)
        @current_user = current_user
        @feature_setting = feature_setting
      end

      def track
        return ServiceResponse.success unless ::Ai::SelfHostedDapBilling.should_bill?(feature_setting)

        grpc_client.track_self_hosted_client_event(request_id: SecureRandom.uuid,
          feature_qualified_name: FEATURE_QUALIFIED_NAME, feature_ai_catalog_item: false)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, feature: feature_setting.feature)
        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :current_user, :feature_setting

      def grpc_client
        ::Ai::DuoWorkflow::DuoWorkflowService::Client.new(
          duo_workflow_service_url: ::Gitlab::DuoWorkflow::Client.cloud_connected_url(user: current_user),
          current_user: current_user,
          secure: ::Gitlab::DuoWorkflow::Client.secure?,
          feature_setting: feature_setting
        )
      end
    end
  end
end
