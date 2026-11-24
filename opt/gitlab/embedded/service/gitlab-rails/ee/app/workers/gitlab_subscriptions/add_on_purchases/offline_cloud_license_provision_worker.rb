# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class OfflineCloudLicenseProvisionWorker
      include ::Gitlab::Utils::StrongMemoize
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- Context unnecessary

      data_consistency :sticky
      feature_category :"add-on_provisioning"
      idempotent!

      def perform
        License.reset_current

        return if license.nil? || license.online_cloud_license?

        log_event provision_add_on_purchases
      end

      private

      def license
        License.current
      end
      strong_memoize_attr :license

      # Only the Orbit promo add-on is provisioned from a non-cloud license.
      def provision_add_on_purchases
        provision_service = if license.offline_cloud_license?
                              ::GitlabSubscriptions::AddOnPurchases::SelfManaged::ProvisionServices::AddOns
                            else
                              ::GitlabSubscriptions::AddOnPurchases::SelfManaged::ProvisionServices::OrbitPromo
                            end

        provision_service.new.execute
      end

      def log_event(response)
        Gitlab::AppLogger.info(
          message: 'Offline/Legacy license checked for potentially new add-on purchases',
          license_type: license.license_type,
          subscription_id: license.subscription_id,
          subscription_name: license.subscription_name,
          response: response.to_h
        )
      end
    end
  end
end
