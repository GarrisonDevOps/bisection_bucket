# frozen_string_literal: true

module API
  module Internal
    class ServicePing < ::API::Base
      helpers do
        def authenticate_service_ping_request!
          unauthorized! unless ::ServicePing::InternalApiAuthenticator.verify_api_request(headers)
        end
      end

      namespace 'internal' do
        namespace 'service_ping' do
          desc 'Get the instance identity and Service Ping settings' do
            detail 'Returns the instance identity and Service Ping settings for services that report ' \
              'Service Ping on behalf of this instance. New fields are only added, so older callers keep working.'
            tags 'service_ping'
            success code: 200
            failure [{ code: 401, message: 'Unauthorized' }, { code: 403, message: 'Forbidden' }]
          end
          route_setting :authorization, skip_granular_token_authorization: :service_ping_jwt_auth
          get 'instance', feature_category: :service_ping, urgency: :low do
            verify_workhorse_api!
            authenticate_service_ping_request!

            {
              identity: ::ServicePing::InstanceIdentity.to_h,
              settings: {
                service_ping_enabled: ::ServicePing::ServicePingSettings.enabled_and_consented?,
                service_ping_generation_enabled: ::Gitlab::CurrentSettings.usage_ping_generation_enabled?,
                service_ping_optional_metrics_enabled: ::Gitlab::CurrentSettings.usage_ping_features_enabled?
              }
            }
          end
        end
      end
    end
  end
end
