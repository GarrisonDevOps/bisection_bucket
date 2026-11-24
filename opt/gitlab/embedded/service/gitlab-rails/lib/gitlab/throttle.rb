# frozen_string_literal: true

module Gitlab
  class Throttle
    DEFAULT_RATE_LIMITING_RESPONSE_TEXT = 'Retry later'

    # Each of these settings follows the same pattern of specifying separate
    # authenticated and unauthenticated rates via settings. New throttles should
    # ideally be regular as well.
    REGULAR_THROTTLES = [:api, :packages_api, :files_api, :deprecated_api].freeze

    # The value bypass_header must equal to actually bypass throttling.
    # Single source of truth for ApplicationRateLimiter's bypass check and
    # its synthetic labkit :skip rule match, so they can't drift apart.
    BYPASS_HEADER_VALUE = '1'

    def self.settings
      Gitlab::CurrentSettings.current_application_settings
    end

    # Returns true if we should use the Admin area protected paths throttle
    def self.protected_paths_enabled?
      self.settings.throttle_protected_paths_enabled?
    end

    def self.omnibus_protected_paths_present?
      Rack::Attack.throttles.key?('protected paths')
    end

    def self.bypass_header
      env_value = ENV['GITLAB_THROTTLE_BYPASS_HEADER']
      return unless env_value.present?

      "HTTP_#{env_value.upcase.tr('-', '_')}"
    end

    class << self
      def options(throttle, authenticated:)
        fragment = throttle_fragment!(throttle, authenticated: authenticated)

        # rubocop:disable GitlabSecurity/PublicSend
        limit_proc = proc { |req| settings.public_send("#{fragment}_requests_per_period") }
        period_proc = proc { |req| settings.public_send("#{fragment}_period_in_seconds").seconds }
        # rubocop:enable GitlabSecurity/PublicSend

        { limit: limit_proc, period: period_proc }
      end

      def throttle_fragment!(throttle, authenticated:)
        raise("Unknown throttle: #{throttle}") unless REGULAR_THROTTLES.include?(throttle)

        "throttle_#{'un' unless authenticated}authenticated_#{throttle}"
      end
    end

    def self.unauthenticated_web_options
      # TODO: Columns will be renamed in https://gitlab.com/gitlab-org/gitlab/-/issues/340031
      # Once this is done, web can be made into a regular throttle
      limit_proc = proc { |req| settings.throttle_unauthenticated_requests_per_period }
      period_proc = proc { |req| settings.throttle_unauthenticated_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.authenticated_web_options
      limit_proc = proc { |req| settings.throttle_authenticated_web_requests_per_period }
      period_proc = proc { |req| settings.throttle_authenticated_web_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.protected_paths_options
      limit_proc = proc { |req| settings.throttle_protected_paths_requests_per_period }
      period_proc = proc { |req| settings.throttle_protected_paths_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.throttle_unauthenticated_git_http_options
      limit_proc = proc { |req| settings.throttle_unauthenticated_git_http_requests_per_period }
      period_proc = proc { |req| settings.throttle_unauthenticated_git_http_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.throttle_authenticated_git_http_options
      limit_proc = proc { |req| settings.throttle_authenticated_git_http_requests_per_period }
      period_proc = proc { |req| settings.throttle_authenticated_git_http_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.throttle_authenticated_git_lfs_options
      limit_proc = proc { |req| settings.throttle_authenticated_git_lfs_requests_per_period }
      period_proc = proc { |req| settings.throttle_authenticated_git_lfs_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    # These count per actor and project, alongside the instance-wide throttles above, so
    # an override is an extra ceiling rather than a replacement that would hand an actor
    # a fresh bucket per project they own.
    def self.throttle_unauthenticated_git_http_project_options
      limit_proc = proc { |facts|
        project_git_limit(:unauthenticated_git_http, fact: :unauthenticated_git_http_project, facts: facts,
          default: settings.throttle_unauthenticated_git_http_requests_per_period)
      }
      period_proc = proc { |req| settings.throttle_unauthenticated_git_http_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.throttle_authenticated_git_http_project_options
      limit_proc = proc { |facts|
        project_git_limit(:authenticated_git_http, fact: :authenticated_git_http_project, facts: facts,
          default: settings.throttle_authenticated_git_http_requests_per_period)
      }
      period_proc = proc { |req| settings.throttle_authenticated_git_http_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.throttle_authenticated_git_lfs_project_options
      limit_proc = proc { |facts|
        project_git_limit(:authenticated_git_lfs, fact: :authenticated_git_lfs_project, facts: facts,
          default: settings.throttle_authenticated_git_lfs_requests_per_period)
      }
      period_proc = proc { |req| settings.throttle_authenticated_git_lfs_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    # The overridden limit, from the request's Labkit facts. The matching rule already
    # gated on `fact`; anything else gets the instance default, so the limit can't
    # activate without the matching key.
    def self.project_git_limit(throttle, fact:, facts:, default:)
      override_key = facts.is_a?(Hash) && facts[fact]
      return default unless override_key

      ::Gitlab::RateLimit::ProjectThrottleLimits.limit_for_key(throttle, override_key, default: default)
    end
    private_class_method :project_git_limit

    def self.throttle_authenticated_dependency_proxy_options
      limit_proc = proc { |req| settings.throttle_authenticated_dependency_proxy_requests_per_period }
      period_proc = proc { |req| settings.throttle_authenticated_dependency_proxy_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.throttle_authenticated_mcp_options
      limit_proc = proc { |req| settings.throttle_authenticated_mcp_requests_per_period }
      period_proc = proc { |req| settings.throttle_authenticated_mcp_period_in_seconds.seconds }

      { limit: limit_proc, period: period_proc }
    end

    def self.rate_limiting_response_text
      (settings.rate_limiting_response_text.presence || DEFAULT_RATE_LIMITING_RESPONSE_TEXT) + "\n"
    end
  end
end
