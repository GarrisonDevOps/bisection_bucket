# frozen_string_literal: true

module API
  module Internal
    class Workhorse < ::API::Base
      before do
        verify_workhorse_api!
        content_type Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE
      end

      helpers do
        def request_authenticated?
          authenticator = Gitlab::Auth::RequestAuthenticator.new(request)
          return true if authenticator.find_authenticated_requester([:api])

          # Look up user from warden, ignoring the absence of a CSRF token. For
          # web users the CSRF token can be in the POST form data but Workhorse
          # does not propagate the form data to us.
          !!request.env['warden']&.authenticate
        end

        # Rails-bound decisions carry a cause so Workhorse can log the fallback.
        def register_routing_decision
          return { destination: 'rails', reason: 'flag_disabled' } unless
            Feature.enabled?(:proxy_dcr_to_iam, Feature.current_request)

          return { destination: 'rails', reason: 'rate_limited' } if register_rate_limited?

          { destination: 'iam' }
        end

        def register_rate_limited?
          return false if ::Oauth::DynamicRegistrationsController.skip_rate_limit?

          # Apply the controller's per-IP limit until clients reach IAM through Cloudflare (gitlab-org/gitlab#623572).
          #
          # See https://gitlab.com/gitlab-org/gitlab/-/blob/c1cef0454480c09d7053bffe950f3e3e643d25b2/lib/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits.rb#L425-431
          ::Gitlab::ApplicationRateLimiter.throttled_request?(
            request, nil, :oauth_dynamic_registration, scope: { ip: request.ip }
          )
        end
      end

      namespace 'internal' do
        namespace 'workhorse' do
          route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
          post 'authorize_upload', feature_category: :not_owned do # rubocop:todo Gitlab/AvoidFeatureCategoryNotOwned -- Pre-existing: serves uploads across multiple feature areas (repo files, LFS, packages, registry, CI artifacts); no single owner.
            unauthorized! unless request_authenticated?

            status 200
            { TempPath: File.join(::Gitlab.config.uploads.storage_path, 'uploads/tmp') }
          end

          desc 'OAuth routing decision for Workhorse' do
            detail 'Workhorse calls this per OAuth request to decide whether to proxy ' \
              'to the IAM Auth Service or pass through to Rails, based on the ' \
              'proxy_oauth_requests_to_iam_service feature flag for the OAuth ' \
              'application identified by client_id. See gitlab-org/gitlab#594504. ' \
              'A missing or unknown client_id returns "iam" only when the ' \
              'route_unknown_oauth_clients_to_iam feature flag is enabled, because dynamic ' \
              'clients exist only there. See https://gitlab.com/gitlab-org/gitlab/-/work_items/623577.'
            success code: 200, message: 'Routing decision: "iam" or "rails"'
            tags %w[internal]
          end
          params do
            optional :client_id, type: String, limit: 255,
              desc: 'The OAuth application uid extracted by Workhorse from the OAuth request'
          end
          route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
          post 'oauth_routing', feature_category: :system_access do
            application = ::Authn::OauthApplication.by_uid(params[:client_id])
            route_to_iam =
              if application
                application.iam_routing_enabled?
              else
                Feature.enabled?(:route_unknown_oauth_clients_to_iam, :instance)
              end

            status 200
            { destination: route_to_iam ? 'iam' : 'rails' }
          end

          desc 'OAuth dynamic client registration routing decision for Workhorse' do
            detail 'Workhorse calls this on POST /oauth/register to decide whether ' \
              'to proxy dynamic client registration to the IAM Auth Service. ' \
              'Registration creates a new client, so there is no client_id to key a ' \
              'per-application decision on. The answer is the per-request state of ' \
              'the proxy_dcr_to_iam feature flag. A client IP over the ' \
              'oauth_dynamic_registration rate limit routes to Rails, which returns the 429. See ' \
              'https://gitlab.com/gitlab-org/gitlab/-/work_items/623577.'
            success code: 200,
              message: 'Routing decision: "iam", or "rails" with a "reason" naming ' \
                'the cause ("flag_disabled" or "rate_limited")'
            tags %w[internal]
          end
          route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
          post 'register_routing', feature_category: :system_access do
            status 200
            register_routing_decision
          end
        end
      end
    end
  end
end
