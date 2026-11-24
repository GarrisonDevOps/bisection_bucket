# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module RequestAuthenticator
        extend ::Gitlab::Utils::Override

        private

        override :find_user_for_graphql_api_request
        def find_user_for_graphql_api_request
          find_user_from_geo_token || super
        end

        override :graphql_authorization_scopes
        def graphql_authorization_scopes
          super + [:ai_features, :ai_workflows]
        end

        # The rate limiters identify the requester before the endpoint authenticates it, and the endpoint already
        # streams this event, so auditing here too would send it once per lookup instead of once per request.
        override :audit_job_token_authentication
        def audit_job_token_authentication(_user); end

        # Identifies ID-token exchanges by user, as job-token exchanges are, so
        # jobs behind one runner IP don't share the unauthenticated API limit.
        override :find_user_from_any_authentication_method
        def find_user_from_any_authentication_method(request_format)
          find_user_from_ci_id_token || super
        end

        # Any API request, as for job tokens: only a bearer whose `aud` is the exchange
        # is claimed, and only the exchange endpoint accepts one.
        override :route_authentication_setting
        def route_authentication_setting
          super.merge(ci_id_token_allowed: api_request?)
        end
      end
    end
  end
end
