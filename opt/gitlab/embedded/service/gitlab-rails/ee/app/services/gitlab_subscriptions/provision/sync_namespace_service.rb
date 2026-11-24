# frozen_string_literal: true

# Service for syncing namespace provisions from CustomersDot
# @param namespace [Group] the namespace to sync
# @param params [Hash] provision params containing:
#   - event_type [String] must be "sync"
#   - base_product [Hash] plan parameters
#   - storage [Hash] storage parameters
#   - compute_minutes [Hash] compute minutes parameters
module GitlabSubscriptions
  module Provision
    class SyncNamespaceService
      attr_reader :namespace, :params

      def initialize(namespace:, params:)
        @namespace = namespace
        @params = params
        @errors = []
      end

      def execute
        payload = {
          base_product: sync_base_product,
          storage: sync_storage,
          compute_minutes: sync_compute_minutes,
          add_on_purchases: sync_add_on_purchases
        }

        # NOTE: always call `run_after_provision_hooks` even if `errors.present?`, because the provision
        # could be `partial success`.
        # For example: `compute_minutes` provision failed, but `add_on_purchases` provision succeed.
        run_after_provision_hooks

        return ServiceResponse.success(message: nil, payload: payload) if errors.blank?

        ServiceResponse.error(message: format_message(errors), payload: payload)
      end

      private

      attr_reader :errors

      def base_product_params
        params[:base_product]
      end

      def compute_minutes_params
        params[:compute_minutes]
      end

      def storage_params
        params[:storage]
      end

      def add_on_purchases_params
        params[:add_on_purchases]
      end

      def sync_base_product
        return if base_product_params.blank?

        error_messages = []
        error_messages.concat(sync_namespace.to_a)
        error_messages.concat(sync_namespace_settings.to_a)
        return sync_success_response if error_messages.blank?

        sync_error_response(error_messages)
      end

      def sync_namespace
        return if namespace.update(gitlab_subscription_attributes: base_product_params)

        namespace.errors.full_messages
      end

      def sync_namespace_settings
        return unless base_product_params.key?(:contract_overages_allowed)
        return if base_product_params[:contract_overages_allowed] == true

        settings = namespace.namespace_settings
        return unless settings
        return if settings.update(seat_control: ::ApplicationSetting::SEAT_CONTROL_BLOCK_OVERAGES)

        settings.errors.full_messages
      end

      def sync_storage
        return if storage_params.blank?

        return sync_success_response if namespace.reset.update(storage_params)

        sync_error_response(namespace.errors.full_messages)
      end

      def sync_compute_minutes
        return if compute_minutes_params.blank?

        result = SyncComputeMinutesService.new(namespace: namespace.reset, params: compute_minutes_params).execute
        return sync_success_response if result.success?

        sync_error_response(result.message)
      end

      def sync_add_on_purchases
        return if add_on_purchases_params.blank?

        result = ::GitlabSubscriptions::AddOnPurchases::GitlabCom::ProvisionService.new(
          namespace.reset,
          add_on_purchases_params
        ).execute
        return sync_success_response if result.success?

        sync_error_response(result.message)
      end

      def run_after_provision_hooks
        ::GitlabSubscriptions::Duo::EnableCodeReviewFlowWorker.perform_async(namespace.id)
      end

      def sync_success_response
        {
          status: :success
        }
      end

      def sync_error_response(message)
        errors << message

        {
          status: :error,
          message: format_message(message)
        }
      end

      def format_message(message)
        Array(message).flatten.compact.join(', ')
      end
    end
  end
end
