# frozen_string_literal: true

module Observability
  class O11yProvisioningClient
    include Gitlab::Utils::StrongMemoize

    def provision_namespace(namespace, user)
      return { success: false, error: 'Observability provisioner is not configured' } unless configured?

      api_request_data = build_api_request_data(namespace, user)
      api_success = make_api_request(api_request_data)

      if api_success
        {
          success: true,
          settings_params: build_settings_params(api_request_data)
        }
      else
        {
          success: false,
          error: 'API call failed for observability group setting'
        }
      end
    end

    private

    def configured?
      provisioner_url.present? && api_key.present?
    end

    def provisioner_url
      Gitlab::CurrentSettings.o11y_provisioner_url
    end
    strong_memoize_attr :provisioner_url

    def api_key
      Gitlab::CurrentSettings.o11y_provisioner_api_key
    end
    strong_memoize_attr :api_key

    def build_api_request_data(namespace, user)
      {
        group_id: namespace.id,
        email: user.email,
        password: SecureRandom.hex(16),
        encryption_key: SecureRandom.hex(32),
        user_name: user.name,
        group_path: namespace.full_path,
        is_user: namespace.user_namespace?
      }
    end

    def build_settings_params(api_request_data)
      {
        o11y_service_name: api_request_data[:group_id].to_s,
        o11y_service_user_email: "#{api_request_data[:group_id]}@gitlab-o11y.com",
        o11y_service_password: api_request_data[:password],
        o11y_service_post_message_encryption_key: api_request_data[:encryption_key]
      }
    end

    def make_api_request(api_request_data)
      response = Gitlab::HTTP.post(
        provisioner_url,
        body: { o11y_provision_request: api_request_data }.to_json,
        headers: {
          'Content-Type' => 'application/json',
          'User-Agent' => "GitLab/#{Gitlab::VERSION}",
          'X-API-Key' => api_key
        },
        timeout: 30
      )

      response.success?
    rescue *Gitlab::HTTP::HTTP_ERRORS => e
      handle_api_error(e, api_request_data[:group_id])
      false
    end

    def handle_api_error(error, group_id)
      filtered_message = case error
                         when Gitlab::HTTP_V2::BlockedUrlError, Gitlab::HTTP_V2::RedirectionTooDeep
                           Gitlab::UrlSanitizer.sanitize(error.message)
                         else
                           error.message
                         end

      log_error(
        message: 'API request error for observability setting',
        group_id: group_id,
        error: filtered_message,
        error_class: error.class.name
      )
    end

    def log_error(data)
      Gitlab::AppLogger.error(data)
    end
  end
end
