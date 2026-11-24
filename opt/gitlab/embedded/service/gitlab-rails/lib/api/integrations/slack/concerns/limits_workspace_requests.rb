# frozen_string_literal: true

module API
  class Integrations
    module Slack
      module Concerns
        # Per-workspace rate limit for requests Slack sends to GitLab. Call
        # only after the request signature has been verified, so unsigned
        # traffic can't burn a workspace's budget.
        #
        # A throttled request is dropped with a 2xx response, never a 429:
        # Slack retries non-2xx deliveries up to three times and disables
        # the app's event subscriptions for every workspace once 95% of
        # deliveries fail in an hour. See https://docs.slack.dev/apis/events-api.
        module LimitsWorkspaceRequests
          extend ActiveSupport::Concern

          included do
            helpers do
              def slack_workspace_throttled?(key, team_id)
                return false if team_id.blank?

                throttled = ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: { slack_workspace: team_id })
                return false unless throttled

                log_slack_workspace_throttle(key, team_id)

                return false unless ::Feature.enabled?(:slack_app_workspace_rate_limit, :instance)

                header 'RateLimit-Name', key.to_s

                true
              end

              # Same shape as ApplicationRateLimiter.log_request, plus the
              # workspace: the request has no user, so without it the log
              # cannot tell which tenant is over the limit.
              def log_slack_workspace_throttle(key, team_id)
                ::Gitlab::AuthLogger.error(
                  message: 'Application_Rate_Limiter_Request',
                  env: :"#{key}_request_limit",
                  remote_ip: request.ip,
                  method: request.request_method,
                  path: request.path,
                  slack_workspace: team_id
                )
              end
            end
          end
        end
      end
    end
  end
end
