# frozen_string_literal: true

# Activating self-managed instances
# Part of Cloud Licensing https://gitlab.com/groups/gitlab-org/-/epics/1735
module GitlabSubscriptions
  class ActivateService
    include Gitlab::Utils::StrongMemoize

    ERROR_MESSAGES = {
      not_self_managed: 'Not self-managed instance'
    }.freeze

    def execute(activation_code, automated: false)
      return error(ERROR_MESSAGES[:not_self_managed]) if Gitlab.com?

      response = client.activate(activation_code, automated: automated)

      return response unless response[:success]

      license = find_or_initialize_cloud_license(response[:license_key])
      license.last_synced_at = Time.current

      if license.save
        payload = update_license_dependencies(response, license)
        sync_service_token

        {
          success: true,
          license: license,
          future_subscriptions: payload[:future_subscriptions]
        }
      else
        error(license.errors.full_messages)
      end
    rescue StandardError => e
      error(e.message)
    end

    private

    def sync_service_token
      Gitlab::SeatLinkData.new(refresh_token: true).sync
    end

    def client
      Gitlab::SubscriptionPortal::Client
    end

    def error(message)
      { success: false, errors: Array(message) }
    end

    def find_or_initialize_cloud_license(license_key)
      return License.current.reset if License.current_cloud_license?(license_key)

      License.new(data: license_key, cloud: true)
    end

    def update_license_dependencies(response, license)
      ::GitlabSubscriptions::UpdateLicenseDependenciesService.new(
        future_subscriptions: response[:future_subscriptions],
        license: license,
        new_subscription: response[:new_subscription]
      ).execute
    end
  end
end
