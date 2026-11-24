# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class Client
      include SubscriptionPortal::Clients::Rest
      include SubscriptionPortal::Clients::Graphql

      ResponseError = Class.new(StandardError)

      class << self
        def license_checksum_headers
          license = ::License.current

          raise 'No active license' unless license

          json_headers.merge('X-License-Token' => license.checksum)
        end

        private

        def user_agent
          subscription_portal_url = ::Gitlab::Routing.url_helpers.subscription_portal_url
          subscription_portal_staging_url = ::Gitlab::Routing.url_helpers.subscription_portal_staging_url

          if subscription_portal_url == subscription_portal_staging_url
            Gitlab::Qa.user_agent.presence || "GitLab/#{Gitlab::VERSION}"
          else
            "GitLab/#{Gitlab::VERSION}"
          end
        end

        def default_headers
          {
            "User-Agent" => user_agent
          }
        end

        def json_headers
          default_headers.merge(
            {
              'Accept' => 'application/json',
              'Content-Type' => 'application/json'
            }
          )
        end

        def admin_headers
          json_headers.merge(
            {
              'X-Admin-Email' => Gitlab::SubscriptionPortal::SUBSCRIPTION_PORTAL_ADMIN_EMAIL,
              'X-Admin-Token' => Gitlab::SubscriptionPortal::SUBSCRIPTION_PORTAL_ADMIN_TOKEN
            }
          )
        end

        def customer_headers(email, token)
          json_headers.merge(
            {
              'X-Customer-Email' => email,
              'X-Customer-Token' => token
            }
          )
        end

        def user_auth_headers(user)
          json_headers.merge(
            'Authorization' => "Bearer #{Gitlab::CustomersDot::Jwt.new(user).encoded}"
          )
        end

        def parse_response(http_response)
          parsed_response = http_response.parsed_response

          if http_response.response.is_a?(Net::HTTPSuccess)
            { success: true, data: parsed_response }
          elsif http_response.response.is_a?(Net::HTTPPaymentRequired)
            { success: false, data: { errors: "HTTP status code: 402" } }
          elsif http_response.response.is_a?(Net::HTTPForbidden)
            { success: false, data: { errors: "HTTP status code: 403" } }
          elsif http_response.response.is_a?(Net::HTTPUnprocessableEntity) && parsed_response
            errors = parsed_response.slice('errors', 'error_attribute_map')
            log_error(http_response, errors)
            { success: false, data: errors.symbolize_keys }
          else
            errors = "HTTP status code: #{http_response.code}"
            log_error(http_response, errors)
            { success: false, data: { errors: errors } }
          end.with_indifferent_access
        end

        def log_error(response, errors)
          Gitlab::ErrorTracking.log_exception(
            ResponseError.new('Unsuccessful response code'),
            {
              status: response.code,
              errors: errors
            }
          )
        end
      end
    end
  end
end

# Added for JiHu
# Used in https://jihulab.com/gitlab-cn/gitlab/-/blob/main-jh/jh/lib/jh/gitlab/subscription_portal/client.rb
Gitlab::SubscriptionPortal::Client.prepend_mod
