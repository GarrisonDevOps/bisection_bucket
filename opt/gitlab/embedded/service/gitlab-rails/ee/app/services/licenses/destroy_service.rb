# frozen_string_literal: true

module Licenses
  class DestroyService < ::Licenses::BaseService
    extend ::Gitlab::Utils::Override

    override :execute
    def execute
      raise ActiveRecord::RecordNotFound unless license
      raise Gitlab::Access::AccessDeniedError unless can?(user, :delete_license)

      clear_future_subscriptions
      license.destroy
      update_add_on_purchases
    end

    private

    def clear_future_subscriptions
      return unless license.current?

      Gitlab::CurrentSettings.current_application_settings.update(future_subscriptions: [])
    end

    def update_add_on_purchases
      ::GitlabSubscriptions::AddOnPurchases::SelfManaged::ProvisionServices::AddOns.new.execute
    end
  end
end
