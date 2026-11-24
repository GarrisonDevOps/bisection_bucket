# frozen_string_literal: true

module Ai
  module SelfHostedDapBilling
    def self.should_bill?(feature_setting)
      !!(feature_setting&.self_hosted? &&
        self_hosted_dap_billing_enabled?)
    end

    def self.self_hosted_dap_billing_enabled?
      # Prevent accidental billing charges during local development and testing
      return false if development_env_and_not_enabled?
      # There is no self-hosted billing on gitlab.com instance
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      # There is no self-hosted billing on offline cloud license. Offline
      # cloud licenses use a different SKU for self-hosted DAP billing.
      ::License.current&.online_cloud_license?
    end

    def self.development_env_and_not_enabled?
      Rails.env.development? &&
        !::Gitlab::Utils.to_boolean(ENV['SELF_HOSTED_DAP_BILLING_ENABLED'], default: false)
    end
    private_class_method :development_env_and_not_enabled?
  end
end
