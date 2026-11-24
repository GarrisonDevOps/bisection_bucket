# frozen_string_literal: true

module EE
  module API
    module ImportGithubOauthWebhooks
      extend ActiveSupport::Concern

      prepended do
        helpers do
          extend ::Gitlab::Utils::Override

          override :receive_github_oauth_webhook!
          def receive_github_oauth_webhook!(project)
            result = ::Import::Sync::Github::Oauth::WebhookReceiverService.execute(project, request: request)

            case result.reason
            when :not_found
              not_found!('Project')
            when :bad_request
              bad_request!(result.message)
            when :rate_limited
              rate_limit_key = ::Import::Sync::Github::Oauth::WebhookReceiverService::RATE_LIMIT_KEY
              header['RateLimit-Name'] = rate_limit_key.to_s
              retry_after = ::Gitlab::ApplicationRateLimiter.period_for(rate_limit_key)
              too_many_requests!(result.message, retry_after: retry_after)
            end
          end
        end
      end
    end
  end
end
