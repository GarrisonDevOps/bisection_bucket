# frozen_string_literal: true

# Activating self-managed instances
# Part of Cloud Licensing https://gitlab.com/groups/gitlab-org/-/epics/1735
module GitlabSubscriptions
  class UpdateLicenseDependenciesService
    include Gitlab::Utils::StrongMemoize

    def initialize(future_subscriptions:, license:, new_subscription:)
      @future_subscriptions = future_subscriptions
      @license = license
      @new_subscription = new_subscription
    end

    def execute
      save_future_subscriptions
      update_add_on_purchases
      auto_enable_duo_core_features
      auto_enable_restricted_access

      { future_subscriptions: application_settings.future_subscriptions }
    end

    private

    attr_reader :future_subscriptions, :license, :new_subscription

    def save_future_subscriptions
      future_subscriptions_value = future_subscriptions.presence || []

      application_settings.update!(future_subscriptions: future_subscriptions_value)
    rescue ActiveRecord::ActiveRecordError => err
      Gitlab::ErrorTracking.track_and_raise_for_dev_exception(err)
    end

    def application_settings
      Gitlab::CurrentSettings.current_application_settings
    end
    strong_memoize_attr :application_settings

    def update_add_on_purchases
      ::GitlabSubscriptions::AddOnPurchases::SelfManaged::ProvisionServices::AddOns.new.execute
    end

    def auto_enable_duo_core_features
      return unless auto_enable_duo_core_features?

      ai_setting.update!(duo_core_features_enabled: true)
    rescue ActiveRecord::ActiveRecordError => err
      Gitlab::ErrorTracking.track_and_raise_for_dev_exception(err)
    end

    def auto_enable_duo_core_features?
      return false unless new_subscription.present?
      return false unless license&.started?
      return false unless ai_setting
      return false unless no_user_action_on_duo_core_setting?
      return false unless active_duo_core_add_on?

      true
    end

    def no_user_action_on_duo_core_setting?
      ai_setting.duo_core_features_enabled.nil?
    end

    def ai_setting
      # License activation is instance-scoped and can run outside request
      # context (for example, boot-time license loading), so it operates on
      # the legacy instance-wide settings row of the default organization.
      organization = ::Organizations::Organization.default_organization # rubocop:disable Gitlab/AvoidDefaultOrganization -- instance-scoped license activation
      return unless organization

      Ai::Setting.for_organization(organization)
    end
    strong_memoize_attr :ai_setting

    def active_duo_core_add_on?
      GitlabSubscriptions::AddOnPurchase.for_self_managed.for_duo_core.active.exists?
    end

    def auto_enable_restricted_access
      return unless auto_enable_restricted_access?

      application_settings.update!(seat_control: ApplicationSetting::SEAT_CONTROL_BLOCK_OVERAGES)
    rescue ActiveRecord::ActiveRecordError => err
      Gitlab::ErrorTracking.track_and_raise_for_dev_exception(err)
    end

    def auto_enable_restricted_access?
      return false unless license
      return false unless license.started?
      return false unless License.feature_available?(:seat_control)

      license.contract_overages_allowed == false
    end
  end
end
