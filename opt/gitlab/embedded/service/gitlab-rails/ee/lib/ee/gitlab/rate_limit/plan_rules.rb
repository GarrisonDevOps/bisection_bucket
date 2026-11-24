# frozen_string_literal: true

module EE
  module Gitlab
    module RateLimit
      module PlanRules
        extend ActiveSupport::Concern

        # Slack sends these unauthenticated from a shared IP pool, so they get a wider per-IP bucket.
        SLACK_APP_RULES = [
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_slack_app_traffic_per_ip', action: :limit,
            match: { requester_id: nil, runner_id: nil, unauthenticated_limits_active: true,
                     unauthenticated_enforced: true, path: ::Gitlab::PathRegex.slack_app_api_route_regex },
            characteristics: %i[ip], limit: 1_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_slack_app_traffic_per_ip_log', action: :log,
            match: { requester_id: nil, runner_id: nil, unauthenticated_limits_active: true,
                     unauthenticated_enforced: false, path: ::Gitlab::PathRegex.slack_app_api_route_regex },
            characteristics: %i[ip], limit: 1_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_slack_app_traffic_per_ip', action: :limit,
            match: { requester_id: nil, runner_id: nil, unauthenticated_limits_active: true,
                     unauthenticated_enforced: true, path: ::Gitlab::PathRegex.slack_app_api_route_regex },
            characteristics: %i[ip], limit: 100, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_slack_app_traffic_per_ip_log', action: :log,
            match: { requester_id: nil, runner_id: nil, unauthenticated_limits_active: true,
                     unauthenticated_enforced: false, path: ::Gitlab::PathRegex.slack_app_api_route_regex },
            characteristics: %i[ip], limit: 100, period: 1.minute
          )
        ].freeze

        PAID_TIERS = [
          ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM,
          ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE
        ].freeze

        UNAUTHENTICATED_EXCLUDED_PATHS = [
          { nre: ::Gitlab::PathRegex.repository_git_http_route_regex },
          { nre: ::Gitlab::PathRegex.jira_connect_atlassian_route_regex },
          { nre: ::Gitlab::PathRegex.jira_connect_branch_route_regex },
          { nre: ::Gitlab::PathRegex.group_scim_api_route_regex },
          { nre: ::Gitlab::PathRegex.slack_app_api_route_regex },
          { nre: ::Gitlab::PathRegex.dependency_proxy_containers_route_regex },
          { nre: ::Gitlab::PathRegex.sign_in_flow_route_regex },
          { nre: ::Gitlab::PathRegex.oauth_token_grant_route_regex },
          { nre: ::Gitlab::PathRegex.runner_registration_api_route_regex },
          { nre: ::Gitlab::PathRegex.discovery_document_route_regex },
          { nre: ::Gitlab::PathRegex.oauth_dynamic_registration_route_regex },
          { nre: ::Gitlab::PathRegex.unleash_api_route_regex },
          { nre: ::Gitlab::PathRegex.deprecated_secure_files_installer_route_regex },
          { nre: ::Gitlab::PathRegex.pipeline_trigger_api_route_regex },
          { nre: ::Gitlab::PathRegex.alert_notification_route_regex },
          { nre: ::Gitlab::PathRegex.mailgun_webhook_route_regex },
          { nre: ::Gitlab::PathRegex.haproxy_api_health_check_route_regex },
          { nre: ::Gitlab::PathRegex.home_page_route_regex },
          { nre: ::Gitlab::PathRegex.sign_up_flow_route_regex },
          { nre: ::Gitlab::PathRegex.account_recovery_route_regex },
          { nre: ::Gitlab::PathRegex.trial_registration_route_regex }
        ].freeze

        # A client with an expired OAuth token refreshes it on a 401. Counted per IP, a stale client uses up the
        # shared budget and the 429 hides the 401. A scanner cannot guess an expired token, so a per-token bucket
        # stays limited. https://gitlab.com/gitlab-com/gl-infra/production-engineering/-/work_items/30160
        #
        # Any user can mint tokens and let them expire, so a per-IP cap follows. The per-token rule comes first:
        # once it blocks, Labkit stops the walk, so the cap only counts requests within their token's limit.
        #
        # expired_oauth_token_enforced already requires unauthenticated_enforced, so these never enforce while
        # the per-IP rules only log.
        #
        # They share UNAUTHENTICATED_EXCLUDED_PATHS: a path free for anonymous requests stays free with an expired
        # token, since dropping the token would make the request anonymous anyway.
        EXPIRED_OAUTH_TOKEN_RULES = [
          ::Labkit::RateLimit::Rule.new(
            name: 'expired_oauth_token_traffic_per_token', action: :limit,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, expired_oauth_token_enforced: true,
                     expired_oauth_token_id: /./,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[expired_oauth_token_id], limit: 60, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'expired_oauth_token_traffic_per_token_log', action: :log,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, expired_oauth_token_enforced: false,
                     expired_oauth_token_id: /./,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[expired_oauth_token_id], limit: 60, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'expired_oauth_token_traffic_per_ip', action: :limit,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, expired_oauth_token_enforced: true,
                     expired_oauth_token_id: /./,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[ip], limit: 1_200, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'expired_oauth_token_traffic_per_ip_log', action: :log,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, expired_oauth_token_enforced: false,
                     expired_oauth_token_id: /./,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[ip], limit: 1_200, period: 1.hour
          )
        ].freeze

        # Users behind one office IP open their company's pages anonymously to reach sign-in, often SAML (a paid
        # feature), so anonymous requests to paid namespaces get a per-IP bucket big enough for a busy office.
        UNAUTHENTICATED_RULES = [
          ::Labkit::RateLimit::Rule.new(
            name: 'unauthenticated_traffic_per_ip', action: :limit,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, unauthenticated_enforced: true,
                     target_namespace_plan: { noneOf: PAID_TIERS },
                     expired_oauth_token_enforced: false,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[ip], limit: 60, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'unauthenticated_traffic_per_ip_log', action: :log,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, unauthenticated_enforced: false,
                     target_namespace_plan: { noneOf: PAID_TIERS },
                     expired_oauth_token_enforced: false,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[ip], limit: 60, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'unauthenticated_paid_namespace_traffic_per_ip', action: :limit,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, unauthenticated_enforced: true,
                     target_namespace_plan: { oneOf: PAID_TIERS },
                     expired_oauth_token_enforced: false,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[ip], limit: 10_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'unauthenticated_paid_namespace_traffic_per_ip_log', action: :log,
            match: { requester_id: nil, runner_id: nil,
                     unauthenticated_limits_active: true, unauthenticated_enforced: false,
                     target_namespace_plan: { oneOf: PAID_TIERS },
                     expired_oauth_token_enforced: false,
                     path: UNAUTHENTICATED_EXCLUDED_PATHS },
            characteristics: %i[ip], limit: 10_000, period: 1.hour
          )
        ].freeze

        # The headers would say whether an anonymous request matched a paid namespace, even a private one.
        # Both rules keep their counts out of the headers and share one name. Their periods must match, or
        # Retry-After would tell them apart.
        CONCEALED_RULES = {
          'unauthenticated_traffic_per_ip' => 'unauthenticated_traffic_per_ip',
          'unauthenticated_paid_namespace_traffic_per_ip' => 'unauthenticated_traffic_per_ip'
        }.freeze

        PER_USER_EXCLUDED_PATHS = [
          { nre: ::Gitlab::PathRegex.usage_data_telemetry_api_route_regex },
          { nre: ::Gitlab::PathRegex.git_operation_continuation_route_regex }
        ].freeze

        # Paths with their own Free burst bucket, left out of the API and web buckets.
        FREE_BURST_EXCLUDED_PATHS = [
          *PER_USER_EXCLUDED_PATHS,
          { nre: ::Gitlab::PathRegex.git_or_dependency_proxy_route_regex },
          { nre: ::Gitlab::PathRegex.upload_or_pwa_manifest_route_regex }
        ].freeze

        # Per user the limits are the published ones, so each budget is a :limit rule
        # and a :log twin split on the enforce flag. Limits per
        # https://docs.gitlab.com/user/gitlab_com/rate_limits/#rate-limits-by-plan.
        #
        # Each rule states info-gates-enforce itself rather than reading a combined
        # fact, which is why both plan_limits_<plan>_info and _enforce appear here.
        PLAN_RULES = [
          # Free - per user, enforced
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: true,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 5_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_traffic_per_user_free_plan_log', action: :log,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: false,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 5_000, period: 1.hour
          ),
          # Every counted request falls into exactly one Free burst bucket. The web UI gets the larger budget,
          # since one page load sends many background requests, and its images and PWA manifest get their own.
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: true,
                     web_or_frontend: false,
                     path: FREE_BURST_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 100, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_traffic_per_user_free_plan_log', action: :log,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: false,
                     web_or_frontend: false,
                     path: FREE_BURST_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 100, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_git_and_dependency_proxy_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: true,
                     path: [
                       *PER_USER_EXCLUDED_PATHS,
                       { re: ::Gitlab::PathRegex.git_or_dependency_proxy_route_regex }
                     ] },
            characteristics: %i[requester_type requester_id], limit: 100, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_git_and_dependency_proxy_traffic_per_user_free_plan_log', action: :log,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: false,
                     path: [
                       *PER_USER_EXCLUDED_PATHS,
                       { re: ::Gitlab::PathRegex.git_or_dependency_proxy_route_regex }
                     ] },
            characteristics: %i[requester_type requester_id], limit: 100, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_web_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: true,
                     web_or_frontend: true,
                     path: FREE_BURST_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 300, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_web_traffic_per_user_free_plan_log', action: :log,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: false,
                     web_or_frontend: true,
                     path: FREE_BURST_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 300, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_upload_and_pwa_manifest_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: true,
                     path: [
                       *PER_USER_EXCLUDED_PATHS,
                       { nre: ::Gitlab::PathRegex.git_or_dependency_proxy_route_regex },
                       { re: ::Gitlab::PathRegex.upload_or_pwa_manifest_route_regex }
                     ] },
            characteristics: %i[requester_type requester_id], limit: 300, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_upload_and_pwa_manifest_traffic_per_user_free_plan_log', action: :log,
            match: { requester_plan: 'free', requester_id: /./,
                     plan_limits_free_info: true, plan_limits_free_enforce: false,
                     path: [
                       *PER_USER_EXCLUDED_PATHS,
                       { nre: ::Gitlab::PathRegex.git_or_dependency_proxy_route_regex },
                       { re: ::Gitlab::PathRegex.upload_or_pwa_manifest_route_regex }
                     ] },
            characteristics: %i[requester_type requester_id], limit: 300, period: 1.minute
          ),

          # Premium - per user, enforced
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_traffic_per_user_premium_plan', action: :limit,
            match: { requester_plan: 'premium', requester_id: /./,
                     plan_limits_premium_info: true, plan_limits_premium_enforce: true,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 15_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_traffic_per_user_premium_plan_log', action: :log,
            match: { requester_plan: 'premium', requester_id: /./,
                     plan_limits_premium_info: true, plan_limits_premium_enforce: false,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 15_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_traffic_per_user_premium_plan', action: :limit,
            match: { requester_plan: 'premium', requester_id: /./,
                     plan_limits_premium_info: true, plan_limits_premium_enforce: true,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 1_250, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_traffic_per_user_premium_plan_log', action: :log,
            match: { requester_plan: 'premium', requester_id: /./,
                     plan_limits_premium_info: true, plan_limits_premium_enforce: false,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 1_250, period: 1.minute
          ),

          # Ultimate - per user, enforced
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_traffic_per_user_ultimate_plan', action: :limit,
            match: { requester_plan: 'ultimate', requester_id: /./,
                     plan_limits_ultimate_info: true, plan_limits_ultimate_enforce: true,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 25_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_traffic_per_user_ultimate_plan_log', action: :log,
            match: { requester_plan: 'ultimate', requester_id: /./,
                     plan_limits_ultimate_info: true, plan_limits_ultimate_enforce: false,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 25_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_traffic_per_user_ultimate_plan', action: :limit,
            match: { requester_plan: 'ultimate', requester_id: /./,
                     plan_limits_ultimate_info: true, plan_limits_ultimate_enforce: true,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 2_000, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_traffic_per_user_ultimate_plan_log', action: :log,
            match: { requester_plan: 'ultimate', requester_id: /./,
                     plan_limits_ultimate_info: true, plan_limits_ultimate_enforce: false,
                     path: PER_USER_EXCLUDED_PATHS },
            characteristics: %i[requester_type requester_id], limit: 2_000, period: 1.minute
          )
        ].freeze

        MCP_PATH_REGEX = ::Gitlab::RateLimit::RequestClassification::MCP_PATH_REGEX

        MCP_RULES = [
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_mcp_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./,
                     mcp_sustained_limits_free_info: true, mcp_sustained_limits_free_enforce: true,
                     path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 3_600, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_mcp_traffic_per_user_free_plan_log', action: :log,
            match: { requester_plan: 'free', requester_id: /./,
                     mcp_sustained_limits_free_info: true, mcp_sustained_limits_free_enforce: false,
                     path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 3_600, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_mcp_traffic_per_user_free_plan', action: :limit,
            match: { requester_plan: 'free', requester_id: /./, path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 60, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_mcp_traffic_per_user_premium_plan', action: :limit,
            match: { requester_plan: 'premium', requester_id: /./,
                     mcp_sustained_limits_premium_info: true, mcp_sustained_limits_premium_enforce: true,
                     path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 5_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_mcp_traffic_per_user_premium_plan_log', action: :log,
            match: { requester_plan: 'premium', requester_id: /./,
                     mcp_sustained_limits_premium_info: true, mcp_sustained_limits_premium_enforce: false,
                     path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 5_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_mcp_traffic_per_user_premium_plan', action: :limit,
            match: { requester_plan: 'premium', requester_id: /./, path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 600, period: 1.minute
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_mcp_traffic_per_user_ultimate_plan', action: :limit,
            match: { requester_plan: 'ultimate', requester_id: /./,
                     mcp_sustained_limits_ultimate_info: true, mcp_sustained_limits_ultimate_enforce: true,
                     path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 5_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'sustained_mcp_traffic_per_user_ultimate_plan_log', action: :log,
            match: { requester_plan: 'ultimate', requester_id: /./,
                     mcp_sustained_limits_ultimate_info: true, mcp_sustained_limits_ultimate_enforce: false,
                     path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 5_000, period: 1.hour
          ),
          ::Labkit::RateLimit::Rule.new(
            name: 'burst_mcp_traffic_per_user_ultimate_plan', action: :limit,
            match: { requester_plan: 'ultimate', requester_id: /./, path: MCP_PATH_REGEX },
            characteristics: %i[requester_type requester_id], limit: 600, period: 1.minute
          )
        ].freeze

        RULES = (SLACK_APP_RULES + EXPIRED_OAUTH_TOKEN_RULES + UNAUTHENTICATED_RULES + MCP_RULES + PLAN_RULES).freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :flags
          def flags
            ::Gitlab::RateLimit::FlagPolicy::FLAGS
          end

          override :active?
          def active?
            ::Gitlab::RateLimit::FlagPolicy.gitlab_com?
          end

          override :for_limiter
          def for_limiter(limiter_name)
            return [] unless limiter_name == ::Gitlab::RackAttack::LabkitRateLimit::ThrottleRegistry::GENERAL
            return [] unless ::Gitlab::RateLimit::FlagPolicy.gitlab_com?

            RULES
          end

          override :concealed_rules
          def concealed_rules
            CONCEALED_RULES
          end
        end
      end
    end
  end
end
