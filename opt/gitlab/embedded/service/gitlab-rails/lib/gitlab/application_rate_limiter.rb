# frozen_string_literal: true

module Gitlab
  # This module implements a simple rate limiter that can be used to throttle
  # certain actions. Unlike Rack Attack and Rack::Throttle, which operate at
  # the middleware level, this can be used at the controller or API level.
  # See CheckRateLimit concern for usage.
  module ApplicationRateLimiter
    InvalidKeyError = Class.new(StandardError)
    InvalidScopeError = Class.new(StandardError)
    InvalidResourceError = Class.new(StandardError)

    # Anonymous callers of these keys share one counter today. Kept until each
    # owner requires sign-in or moves anonymous traffic to an IP-keyed rule:
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/638602
    SHARED_ANONYMOUS_COUNTER_KEYS = %i[ci_lint notes_create].freeze

    REPORTED_SKIPPED_LIMITS = Concurrent::Set.new

    class << self
      include ::Gitlab::Utils::StrongMemoize

      # The error message shown to users when a request is throttled. Defined as a
      # method (rather than a constant) so the translation is evaluated at request
      # time, when the user's locale is known, instead of once at class-load time.
      def throttled_error_message
        _('This endpoint has been requested too many times. Try again later.')
      end

      # Increments the given key and returns true if the action should
      # be throttled.
      #
      # @param key [Symbol] Key attribute registered in the labkit rate-limit registry
      # @param scope [Hash{Symbol => ActiveRecord, String, Symbol}] Hash keyed
      #     by the rule's characteristic names, e.g.
      #     { project: project, user: current_user }. AR values contribute
      #     their primary key, primitives their string form; nil values are
      #     dropped (labkit fills the slot with its '_unknown_' sentinel), but
      #     at least one characteristic must have a value.
      # @param resource [ActiveRecord] An ActiveRecord model to count an action
      #     for (e.g. limit unique project (resource) downloads (action) to five
      #     per user (scope)). Only for keys whose rule has count_distinct.
      # @param threshold [Integer] Optional threshold value to override default
      #     one registered in the labkit rate-limit registry
      # @param interval [Integer] Optional interval value to override default
      #     one registered in the labkit rate-limit registry
      # @param users_allowlist [Array<String>] Optional list of usernames to
      #     exclude from the limit, merged with the users named by
      #     GITLAB_THROTTLE_USER_ALLOWLIST. This param will only be functional
      #     if Scope includes a current user.
      # @param peek [Boolean] Optional. When true the key will not be
      #     incremented but the current throttled state will be returned.
      # @param bypass_header [String, nil] Optional. Raw bypass header value,
      #     matched by a synthetic :skip rule (equal to '1') for visibility.
      # @param cost [Integer, nil] Optional. For count-mode keys, the amount to
      #     add to the counter in this one call, so a batch of N can be charged
      #     without N separate calls; defaults to 1 when omitted. Rejected for
      #     set-mode (count_distinct) keys, where it is meaningless. Cost-mode
      #     (resource-usage) keys normally receive their float cost through
      #     resource_usage_throttled?, not here; a cost passed here is still
      #     applied, so do not pass one unless you mean to charge that key.
      #
      # @return [Boolean] Whether or not a request should be throttled
      def throttled?( # rubocop:disable Metrics/ParameterLists -- all optional keyword overrides on an established public API
        key, scope:, resource: nil, threshold: nil, interval: nil, users_allowlist: nil, peek: false,
        bypass_header: nil, cost: nil)
        raise InvalidKeyError, key unless LabkitAdapter.handled?(key)

        scope = validate_scope!(key, scope)

        rule_context = {
          resource_id: resource&.id,
          threshold: threshold,
          interval: interval,
          bypass_header: bypass_header
        }

        _throttled?(
          key,
          scope: scope,
          rule_context: rule_context,
          users_allowlist: users_allowlist,
          peek: peek,
          cost: cost
        )
      end

      # Increments the resource usage for a given key and returns true if the action should
      # be throttled.
      #
      # @param key [Symbol] Key attribute registered in the labkit rate-limit registry
      # @param scope [Hash{Symbol => ActiveRecord, String, Symbol}] Hash keyed
      #     by the rule's characteristic names, e.g.
      #     { project: project, user: current_user }. AR values contribute
      #     their primary key, primitives their string form; nil values are
      #     dropped (labkit fills the slot with its '_unknown_' sentinel), but
      #     at least one characteristic must have a value.
      # @param resource_key [Symbol] Key attribute in SafeRequestStore
      # @param threshold [Integer] Threshold value to override default
      #     one registered in the labkit rate-limit registry
      # @param interval [Integer] Interval value to override default
      #     one registered in the labkit rate-limit registry
      #
      # @return [Boolean] Whether or not a request should be throttled
      #
      # Note: unlike #throttled?, this has no bypass_header: option. Callers
      # are cost-mode/Sidekiq resource-usage checks, not HTTP requests, so there
      # is no bypass header to observe here.
      def resource_usage_throttled?(key, scope:, resource_key:, threshold:, interval:, peek: false)
        scope = validate_scope!(key, scope)

        _throttled?(
          key,
          scope: scope,
          rule_context: { threshold: threshold, interval: interval },
          cost: ::Gitlab::SafeRequestStore[resource_key.to_sym].to_f,
          peek: peek
        )
      end

      # Similar to #throttled? above but checks for the bypass header in the request and logs the request when it is over the rate limit
      #
      # @param request [Http::Request] - Web request used to check the header and log
      # @param current_user [User] Current user of the request, it can be nil
      # @param key [Symbol] Key attribute registered in the labkit rate-limit registry
      # @param scope [Hash{Symbol => ActiveRecord, String, Symbol}] Hash keyed
      #     by the rule's characteristic names, e.g.
      #     { project: project, user: current_user }. AR values contribute
      #     their primary key, primitives their string form; nil values are
      #     dropped (labkit fills the slot with its '_unknown_' sentinel), but
      #     at least one characteristic must have a value.
      # @param resource [ActiveRecord] An ActiveRecord model to count an action
      #     for (e.g. limit unique project (resource) downloads (action) to five
      #     per user (scope)). Only for keys whose rule has count_distinct.
      # @param threshold [Integer] Optional threshold value to override default
      #     one registered in the labkit rate-limit registry
      # @param interval [Integer] Optional interval value to override default
      #     one registered in the labkit rate-limit registry
      # @param users_allowlist [Array<String>] Optional list of usernames to
      #     exclude from the limit, merged with the users named by
      #     GITLAB_THROTTLE_USER_ALLOWLIST. This param will only be functional
      #     if Scope includes a current user.
      # @param peek [Boolean] Optional. When true the key will not be
      #     incremented but the current throttled state will be returned.
      #
      # @return [Boolean] Whether or not a request should be throttled
      #
      def throttled_request?(request, current_user, key, scope:, **options)
        header_name = ::Gitlab::Throttle.bypass_header
        bypass_header = request.get_header(header_name) if header_name.present?

        # Only add :bypass_header when there's an actual value to report, so
        # calls without one keep the exact pre-existing argument shape (callers
        # never pass this key themselves, so there's nothing to preserve otherwise).
        options[:bypass_header] = bypass_header if bypass_header

        throttled?(key, scope: scope, **options).tap do |throttled|
          log_request(request, :"#{key}_request_limit", current_user) if throttled
        end
      end

      # Returns the current rate limited state without incrementing the count.
      #
      # @param key [Symbol] Key attribute registered in the labkit rate-limit registry
      # @param scope [Hash{Symbol => ActiveRecord, String, Symbol}] Hash keyed by the rule's characteristic names, e.g. { project: project, user: current_user }. At least one characteristic must have a value.
      # @param threshold [Integer] Optional threshold value to override default one registered in the labkit rate-limit registry
      # @param interval [Integer] Optional interval value to override default one registered in the labkit rate-limit registry
      # @param users_allowlist [Array<String>] Optional list of usernames to exclude from the limit, merged with the users named by GITLAB_THROTTLE_USER_ALLOWLIST. This param will only be functional if Scope includes a current user.
      #
      # @return [Boolean] Whether or not a request is currently throttled
      #
      # Note: like #resource_usage_throttled?, this has no bypass_header:
      # option: callers have no request in scope to read one from.
      def peek(key, scope:, threshold: nil, interval: nil, users_allowlist: nil)
        throttled?(key, peek: true, scope: scope, threshold: threshold, interval: interval, users_allowlist: users_allowlist)
      end

      # Returns the interval (in seconds) registered for the given rate limit key.
      #
      # @param key [Symbol] Key attribute registered in the labkit rate-limit registry
      # @return [Integer] The interval value in seconds
      def period_for(key)
        LabkitAdapter.period_for(key)
      end

      # Returns the limit a key blocks at for the scope, or 0 when it never blocks there: the key
      # is not handled or has no period, the limit is off, the rule is still in log mode, or the
      # scoped user is allowlisted.
      #
      # @param key [Symbol] Key attribute registered in the labkit rate-limit registry
      # @param scope [Hash{Symbol => ActiveRecord, String, Symbol}] Hash keyed by the rule's characteristic names, e.g. { user: current_user }
      # @param users_allowlist [Array<String>] Optional list of usernames to exclude from the limit, merged with the users named by GITLAB_THROTTLE_USER_ALLOWLIST
      #
      # @return [Integer]
      def enforced_limit_for(key, scope:, users_allowlist: nil)
        return 0 unless limit_applies?(key, scope, users_allowlist)

        limits = LabkitAdapter::SupportedRateLimits
        return 0 if limits.staged?(key) && !limits.enforced?(key, scope)

        limits.limit_for(key).to_i
      end

      # Builds the scope for a polymorphic project-or-group parent, filling
      # only the parent's own characteristic so project and group Redis key
      # shapes stay disjoint. A nil parent (e.g. system hooks) fills neither.
      #
      # @param parent [Project, Group, nil]
      # @return [Hash{Symbol => Project, Group}]
      def parent_scope(parent)
        case parent
        when nil then {}
        when ::Project then { project: parent }
        when ::Group then { group: parent }
        else raise InvalidScopeError, "unsupported rate limit parent: #{parent.class}"
        end
      end

      # Logs request using provided logger
      #
      # @param request [Http::Request] - Web request to be logged
      # @param type [Symbol] A symbol key that represents the request
      # @param current_user [User] Current user of the request, it can be nil
      # @param logger [Logger] Logger to log request to a specific log file. Defaults to Gitlab::AuthLogger
      def log_request(request, type, current_user, logger = Gitlab::AuthLogger)
        request_information = {
          message: 'Application_Rate_Limiter_Request',
          env: type,
          remote_ip: request.ip,
          method: request.request_method,
          path: request_path(request)
        }

        if current_user
          request_information.merge!(
            user_id: current_user.id,
            username: current_user.username
          )
        end

        logger.error(request_information)
      end

      private

      def _throttled?(key, scope:, rule_context:, cost: nil, users_allowlist: nil, peek: false)
        ::Gitlab::Instrumentation::RateLimitingGates.track(key)
        validate_overrides!(key, rule_context)

        return false unless limit_applies?(key, scope, users_allowlist, context: rule_context)

        threshold_value = rule_context[:threshold] ||
          LabkitAdapter::SupportedRateLimits.limit_for(key, context: rule_context)
        return false if threshold_value == 0

        resource_id = rule_context[:resource_id]
        if resource_id && !LabkitAdapter.set_mode?(key)
          # Only count_distinct rules can count a resource, so this call is never limited.
          if report_skipped_limits?
            report_skipped_limit(
              key, :resource, InvalidResourceError.new("resource: is not supported for #{key}, its rule has no count_distinct")
            )
          end

          return false
        end

        validate_scope_values!(key, scope)

        return false if cost && LabkitAdapter.set_mode?(key)

        if peek
          LabkitAdapter.run_peek!(key, scope: scope, context: rule_context)
        else
          LabkitAdapter.run!(key, scope: scope, context: rule_context, cost: cost)
        end
      end

      # Whether +key+ can block +scope+ at all: the scoped user is not allowlisted, the adapter
      # handles the key and its period is not 0. The throttle and enforced_limit_for share it so
      # the two cannot drift apart.
      def limit_applies?(key, scope, users_allowlist, context: nil)
        return false if scoped_user_in_allowlist?(scope, users_allowlist)
        return false unless LabkitAdapter.handled?(key)

        interval = context&.dig(:interval) || LabkitAdapter::SupportedRateLimits.period_for(key, context: context)
        interval != 0
      end

      def validate_overrides!(key, rule_context)
        rule = LabkitAdapter::SupportedRateLimits.rule_for(key)

        validate_override!(key, :threshold, rule.limit) unless rule_context[:threshold].nil?
        validate_override!(key, :interval, rule.period) unless rule_context[:interval].nil?
      end

      def validate_override!(key, override_name, rule_value)
        return if LabkitAdapter::SupportedRateLimits.accepts_context?(rule_value)

        rule_attribute = override_name == :threshold ? 'limit' : 'period'

        raise ArgumentError,
          "#{override_name} override is not supported for #{key}. The registered #{rule_attribute} " \
            'does not accept rule_context; ' \
            'register a context-aware callable to accept per-call overrides.'
      end

      def scoped_user_in_allowlist?(scope, users_allowlist)
        allowlist = Array(users_allowlist) + gitlab_throttle_user_allowlist
        return if allowlist.empty?

        scoped_user = scope[:user]
        return unless scoped_user.is_a?(User)

        username = scoped_user.username.downcase
        allowlist.any? { |u| u.downcase == username }
      end

      def gitlab_throttle_user_allowlist
        ids = ::Gitlab::RackAttack.user_allowlist.to_a
        return [] if ids.empty?

        ::User.id_in(ids).pluck_usernames
      end
      strong_memoize_attr :gitlab_throttle_user_allowlist

      def request_path(request)
        # req is an ActionDispatch::Request
        if request.respond_to?(:filtered_path)
          request.filtered_path
        else
          # req is a Grape::Request < Rack::Request
          other_filtered_path(request)
        end
      end

      def other_filtered_path(request)
        filtered_params = initialize_filtered_params.filter(request.GET)

        if filtered_params.any?
          "#{request.path}?#{filtered_params.to_query}"
        else
          request.fullpath
        end
      end

      def initialize_filtered_params
        ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
      end
      strong_memoize_attr :initialize_filtered_params

      def validate_scope!(key, scope, logger = Gitlab::AuthLogger)
        unless scope.is_a?(Hash) && scope.present?
          logger.warn(
            message: 'Application_Rate_Limiter_Request_With_Invalid_Scope',
            env: :"#{key}_request_limit"
          )

          # "got Hash" reads as a contradiction for {}, so name the empty case.
          problem = scope.is_a?(Hash) ? 'got an empty Hash' : "got #{scope.class}"

          raise InvalidScopeError,
            'scope must be a non-empty characteristic-keyed hash, e.g. { user: current_user } ' \
              "(or { scope: :global } for global rate limits); #{problem}. " \
              "The rule's characteristics are registered in LabkitAdapter::SupportedRateLimits."
        end

        scope = ::Labkit::RateLimit::Identifier.new(scope).attributes
        validate_scope_keys!(key, scope)

        scope
      end

      # A scope key that isn't a characteristic of the rule would silently
      # fall to labkit's '_unknown_' sentinel, collapsing what the caller
      # meant as a per-user (or per-project, ...) limit into one shared
      # bucket. Raise in dev/test so typos are caught immediately; track and
      # continue in production, where labkit ignoring the extra key is safe.
      def validate_scope_keys!(key, scope)
        return unless LabkitAdapter.handled?(key)

        unknown_keys = scope.keys - LabkitAdapter::SupportedRateLimits.rule_for(key).characteristics
        return if unknown_keys.empty?

        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          InvalidScopeError.new("scope keys #{unknown_keys.inspect} are not characteristics of the #{key} rule"),
          rate_limit_key: key
        )
      end

      # With every characteristic blank, labkit fills each slot with '_unknown_',
      # so all such callers share one counter. A partly filled scope is fine.
      # Unknown keys are already reported, so they are not reported twice.
      def validate_scope_values!(key, scope)
        identifier = LabkitAdapter.identifier_for(scope)
        return if identifier.values.any? { |value| !value.to_s.empty? }
        return unless report_skipped_limits? && LabkitAdapter.handled?(key)

        characteristics = LabkitAdapter::SupportedRateLimits.rule_for(key).characteristics
        return unless (scope.keys - characteristics).empty?
        return if SHARED_ANONYMOUS_COUNTER_KEYS.include?(key) && scope.values_at(*characteristics).all?(&:nil?)

        report_skipped_limit(
          key, :scope,
          InvalidScopeError.new("scope has no value for any characteristic #{characteristics.inspect} of the #{key} rule")
        )
      end

      # One event per key and process is enough to find the caller. Dev and test
      # raise on every call, so a spec cannot pass on an earlier report.
      def report_skipped_limit(key, kind, exception)
        return if !Gitlab.dev_or_test_env? && !REPORTED_SKIPPED_LIMITS.add?([key, kind])

        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(exception, rate_limit_key: key)
      end

      def report_skipped_limits?
        ::Feature.enabled?(:rate_limiter_report_shared_or_skipped_limits, :instance, type: :ops)
      end
    end
  end
end

Gitlab::ApplicationRateLimiter.prepend_mod
