# frozen_string_literal: true

module GoogleCloud
  module Compute
    class BaseService < ::BaseContainerService
      VALID_ORDER_BY_COLUMNS = %w[creationTimestamp name].freeze
      VALID_ORDER_BY_DIRECTIONS = %w[asc desc].freeze

      MAX_RESULTS_LIMIT = 500

      ERROR_RESPONSES = {
        saas_only: ServiceResponse.error(message: "This is a SaaS-only feature that can't run here"),
        access_denied: ServiceResponse.error(message: 'Access denied'),
        no_integration: ServiceResponse.error(
          message: "#{Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.title} integration not set"),
        integration_not_active: ServiceResponse.error(
          message: "#{Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.title} integration not active"),
        google_cloud_authentication_error:
          ServiceResponse.error(message: 'Unable to authenticate against Google Cloud'),
        invalid_order_by: ServiceResponse.error(message: 'Invalid order_by value'),
        max_results_out_of_bounds: ServiceResponse.error(message: 'Max results argument is out-of-bounds')
      }.freeze

      GCP_API_ERROR_MESSAGE = 'Unsuccessful Google Cloud API request'

      def execute
        params[:max_results] ||= MAX_RESULTS_LIMIT

        validation_response = validate_before_execute
        return validation_response if validation_response&.error?

        handling_client_errors { call_client }
      end

      private

      def validate_before_execute
        return ERROR_RESPONSES[:saas_only] unless Gitlab::Saas.feature_available?(:google_cloud_support)

        return ERROR_RESPONSES[:access_denied] unless allowed?

        return ERROR_RESPONSES[:no_integration] unless wlif_integration
        return ERROR_RESPONSES[:integration_not_active] unless wlif_integration.operating?

        return ERROR_RESPONSES[:max_results_out_of_bounds] unless (1..MAX_RESULTS_LIMIT).cover?(max_results)
        return ERROR_RESPONSES[:invalid_order_by] unless valid_order_by?(order_by)

        ServiceResponse.success
      end

      def allowed?
        can?(current_user, :read_runner_cloud_provisioning_info, container)
      end

      def valid_order_by?(value)
        return true if value.blank?

        column, direction = value.split(' ')

        return false unless column.in?(VALID_ORDER_BY_COLUMNS)
        return false unless direction.in?(VALID_ORDER_BY_DIRECTIONS)

        true
      end

      def client
        ::GoogleCloud::Compute::Client.new(
          wlif_integration: wlif_integration,
          user: current_user,
          params: params.slice(:google_cloud_project_id).compact
        )
      end

      def wlif_integration
        container.google_cloud_platform_workload_identity_federation_integration
      end
      strong_memoize_attr :wlif_integration

      def max_results
        params[:max_results]
      end

      def filter
        params[:filter]
      end

      def order_by
        params[:order_by]
      end

      def page_token
        params[:page_token]
      end

      def handling_client_errors
        yield
      rescue ::GoogleCloud::AuthenticationError => e
        log_error_with_container_id(message: e.message)
        ERROR_RESPONSES[:google_cloud_authentication_error]
      rescue ::GoogleCloud::ApiError => e
        log_error_with_container_id(message: e.message)
        ServiceResponse.error(message: "#{GCP_API_ERROR_MESSAGE}: #{e.message}")
      end

      def log_error_with_container_id(message:)
        log_error(class_name: self.class.name, container_id: container.id, message: message)
      end
    end
  end
end
