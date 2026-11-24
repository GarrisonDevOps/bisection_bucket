# frozen_string_literal: true

module SecretsManagement
  # Read-only value object describing the Secrets Manager entitlement state
  # for a top-level group (or instance). Resolved from CDot for SaaS and
  # from the local `GitlabSubscriptions::AddOnPurchase` mirror on
  # self-managed installs. No DB, no persistence, no state machine -- this
  # PORO observes, it does not transition.
  class Entitlement < Data.define(
    :state,
    :blocked_reason,
    :grace_period_end_date,
    :trial_started_at,
    :trial_expires_at,
    :credits_remaining,
    :credits_total,
    :on_demand_enabled,
    :beta_program_ended,
    :beta_window_eligible,
    :offline_flex_license
  )
    STATES = %i[trial_eligible trial paid offline_paid blocked ineligible].freeze

    # States in which the beta window can open: only groups that never
    # converted qualify. Shared by #beta_window? and the resolver so the
    # state list has a single source of truth.
    BETA_WINDOW_STATES = %i[trial_eligible ineligible].freeze

    BLOCKED_REASONS = %i[
      trial_expired
      credits_exhausted
      on_demand_disabled
      grace
      subscription_grace_period_expired
    ].freeze

    # Read-only (`:grace`) window past the subscription end_date, derived
    # from the .com plan-downgrade grace so the two cannot drift apart.
    GRACE_DAYS = ::GitlabSubscription::SUBSCRIPTION_GRACE_PERIOD.in_days.to_i

    # `timeout` sets open, read and write alike, and Net::HTTP retries a read
    # timeout once on a GET, so the worst case per stalled call is ~2x this --
    # still under the 5s that Gitlab::Metrics::Subscribers::ExternalHttp counts
    # as a slow request. A bare Float, like the sibling timeout constants:
    # HTTParty honours only Integer or Float and silently ignores anything else.
    DEFAULT_HTTP_TIMEOUT_SECONDS = 2.0

    # Shared cross-request cache window for CI job pickup: EE::Ci::RegisterJobService's
    # job-scheduling gate and EE::Ci::BuildRunnerPresenter's runner payload check both resolve
    # with this `cache_ttl`, so a live resolution from either one warms the same Rails.cache
    # entry and repairs a lost race for the rest of the window instead of denying it.
    JOB_PICKUP_CACHE_TTL = 1.minute

    # `cache_ttl` opts into the same cross-request Rails.cache layer `.for!` uses, but (like the
    # rest of `.for`) only a genuine live resolution is ever written there -- a fail-closed
    # `:ineligible` from a resolution error is never cached, since that would let one transient
    # error deny a namespace for the rest of the window.
    def self.for(namespace, user: nil, http_timeout: default_http_timeout, cache_ttl: nil)
      Resolver.new(namespace, user: user, http_timeout: http_timeout, cache_ttl: cache_ttl).resolve
    end

    # nil drops the option rather than setting it to zero, so `Gitlab::HTTP`'s
    # own defaults apply.
    def self.default_http_timeout
      return unless ::Feature.enabled?(:secrets_manager_entitlement_lkg_fallback, :instance)

      DEFAULT_HTTP_TIMEOUT_SECONDS
    end
    private_class_method :default_http_timeout

    # Like `.for`, but raises on resolution failure instead of failing closed
    # to `:ineligible` -- for callers (billing-event metadata) where an absent
    # state is honest and a wrong `:ineligible` is not. `http_timeout` bounds
    # each underlying CDot call, for latency-sensitive paths. `cache_ttl` opts
    # into a cross-request Rails.cache layer for hot paths that tolerate a stale state.
    #
    # Unlike `.for`, no default: the latency-sensitive callers pass their own
    # budget, and the conversion mutations want none -- they clear the cache
    # first and must reach CDot, where a false timeout reverts the add-on
    # intent.
    def self.for!(namespace, user: nil, http_timeout: nil, cache_ttl: nil)
      Resolver.new(namespace, user: user, http_timeout: http_timeout, cache_ttl: cache_ttl).resolve!
    end

    # Live answer for a user who may just have changed billing consent in the
    # Customers Portal. Raises when CDot cannot answer, without clearing any cache.
    # Bounded like `.for`: a timeout costs only a retry, since nothing is written.
    def self.refresh!(namespace, user: nil)
      Resolver.new(namespace, user: user, http_timeout: DEFAULT_HTTP_TIMEOUT_SECONDS, fresh: true).refresh!
    end

    # Entitlement is only meaningful for top-level groups: a personal
    # namespace's `root_ancestor` is itself (not a Group), so it maps to
    # instance-level entitlement (nil). `namespace` is any Group or Project.
    # Shared by callers that need to resolve the entitlement-relevant
    # namespace for a Group/Project before calling `.for`.
    def self.root_namespace_for(namespace)
      return unless namespace

      root = namespace.root_ancestor
      root.is_a?(::Group) ? root : nil
    end

    # Only `state` is required; every other field defaults to nil so that
    # state-specific constructions (e.g. `:ineligible`) don't have to spell
    # out inapplicable trial / paid fields. `state` and `blocked_reason` are
    # enforced against `STATES` / `BLOCKED_REASONS` so the constants are a
    # contract rather than documentation.
    # rubocop:disable Metrics/ParameterLists -- mirrors the Data.define field list
    def initialize(
      state:,
      blocked_reason: nil,
      grace_period_end_date: nil,
      trial_started_at: nil,
      trial_expires_at: nil,
      credits_remaining: nil,
      credits_total: nil,
      on_demand_enabled: nil,
      beta_program_ended: nil,
      beta_window_eligible: nil,
      offline_flex_license: nil
    )
      validate_state!(state)
      validate_blocked_reason!(state, blocked_reason)
      validate_grace_period_end_date!(blocked_reason, grace_period_end_date)
      super
    end
    # rubocop:enable Metrics/ParameterLists

    def permits_writes?
      return true if beta_window?

      %i[trial paid offline_paid].include?(state)
    end

    def permits_access?
      return true if beta_window?

      %i[trial_eligible trial paid offline_paid].include?(state)
    end

    # Broader than `permits_access?`: `blocked` still permits reads, only `:ineligible` denies them.
    # Also the billing gate for deletes: a namespace that can see its secrets can
    # remove them. Role abilities and the OpenBao ACL still decide who may delete.
    # Used by reads that stay inside Rails (Web UI, GraphQL); paths that hand the
    # client a credential to read straight from OpenBao use `permits_direct_read?`
    # instead (see below).
    def permits_read?
      permits_access? || state == :blocked
    end

    def in_grace?
      state == :blocked && blocked_reason == :grace
    end

    # Narrower than `permits_read?`: only the `grace` window permits direct reads,
    # every other `blocked_reason` denies them. Gates any path that issues a JWT
    # for reading straight from OpenBao (CI pipeline JWT, the non-CI/CD REST
    # access-token endpoint). Web/GraphQL intentionally stay on the broader
    # `permits_read?` since Rails brokers those reads itself.
    #
    # `trial_eligible` loses direct reads once the beta program ends
    # (`beta_program_ended`, always true on online-resolved entitlements):
    # non-converted beta namespaces keep metadata-only visibility via
    # Rails-brokered surfaces, but their pipelines stop reading secrets for free.
    def permits_direct_read?
      return false if state == :trial_eligible && beta_program_ended

      permits_access? || in_grace?
    end

    # Structured reason a write was denied, so callers can surface it
    # without re-querying the resolver. `nil` when writes are permitted.
    # `:blocked` carries its own (always-present) `blocked_reason`;
    # `:trial_eligible` is a state, not a blocked reason, so it maps to
    # `:trial_required` (the actionable reason from the caller's
    # perspective). Anything else left after `permits_writes?` is
    # `:ineligible`. Every branch returns a value from
    # `WriteActionDenialReasonEnum::VALUES`.
    def write_action_denial_reason
      return if permits_writes?

      { blocked: blocked_reason, trial_eligible: :trial_required }.fetch(state, :ineligible)
    end

    private

    # Beta groups that never converted (trial_eligible, or ineligible including
    # the fail-closed path) keep pre-rollout access until the beta program ends.
    # Once a group starts a trial it has converted and follows normal entitlement.
    # The state filter lives in the resolver: `beta_window_eligible` is only set
    # for BETA_WINDOW_STATES on enrolled groups.
    def beta_window?
      beta_window_eligible && !beta_program_ended
    end

    def validate_state!(state)
      return if STATES.include?(state)

      raise ArgumentError, "Unknown state: #{state.inspect} (expected one of #{STATES.inspect})"
    end

    # `blocked_reason` is required when `state` is `:blocked` -- this is
    # what lets `write_action_denial_reason` avoid ever falling back to the
    # raw `:blocked` state, which isn't a valid `WriteActionDenialReasonEnum`
    # value.
    def validate_blocked_reason!(state, blocked_reason)
      if blocked_reason.nil?
        return unless state == :blocked

        raise ArgumentError,
          "blocked_reason is required when state is :blocked (expected one of #{BLOCKED_REASONS.inspect})"
      end

      return if BLOCKED_REASONS.include?(blocked_reason)

      raise ArgumentError,
        "Unknown blocked_reason: #{blocked_reason.inspect} (expected one of #{BLOCKED_REASONS.inspect})"
    end

    # Only the `:grace` window has an end date to count down to; once it
    # elapses (`:subscription_grace_period_expired`) or for any other reason
    # a value here would be misleading.
    def validate_grace_period_end_date!(blocked_reason, grace_period_end_date)
      return if grace_period_end_date.nil?
      return if blocked_reason == :grace

      raise ArgumentError, "grace_period_end_date is only valid when blocked_reason is :grace"
    end
  end
end
