# frozen_string_literal: true

module GitlabSubscriptions
  module Provision
    class SyncComputeMinutesService
      attr_reader :namespace, :params

      def initialize(namespace:, params:)
        @namespace = namespace
        @params = params
      end

      def execute
        sync_shared_minutes!
        # TODO: extend for compute minutes packs

        ServiceResponse.success
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.message)
      end

      private

      def sync_shared_minutes!
        return if shared_minutes_params.blank?

        update_attrs = shared_minutes_params.dup.tap do |result|
          if reset_last_compute_minutes_notification?
            result[:last_ci_minutes_notification_at] = nil
            result[:last_ci_minutes_usage_notification_level] = nil
          end
        end

        return if update_attrs.blank?

        namespace.update!(update_attrs)

        # Reset compute minutes usage data
        ::Ci::Runner.instance_type.each(&:tick_runner_queue) if reset_last_compute_minutes_notification?
        ::Ci::Minutes::RefreshCachedDataService.new(namespace).execute
        ::Ci::Minutes::NamespaceMonthlyUsage.reset_current_notification_level(namespace)
      end

      def shared_minutes_params
        @shared_minutes_params ||= params.slice(:shared_runners_minutes_limit, :extra_shared_runners_minutes_limit)
      end

      # Reset last_ci_minutes_notification_at if customer purchased extra compute minutes.
      def reset_last_compute_minutes_notification?
        shared_minutes_params[:extra_shared_runners_minutes_limit].present?
      end
    end
  end
end
