# frozen_string_literal: true

module SecretsManagement
  class Entitlement
    # Resolves `SecretsManagement::Entitlement` for a top-level group (or
    # instance).
    #
    # Routing splits on live CDot connectivity:
    #
    # - gitlab.com + online-cloud-licensed self-managed
    #   -> online branch. Authoritative source is CDot for trial / on-demand /
    #   blocked state. On self-managed, the grace window for lapsed customers
    #   anchors on the local `AddOnPurchase` mirror when there is one, else on
    #   the license term end -- neither surfaces trial nor on-demand state.
    #
    # - offline-cloud-licensed self-managed (air-gapped)
    #   -> local `GitlabSubscriptions::AddOnPurchase` mirror. No CDot
    #   connectivity means trial / on-demand / grace are unreachable;
    #   the only states observable here are `:offline_paid` and
    #   `:blocked + :subscription_grace_period_expired`.
    #
    # `Gitlab.com?` is OR'd alongside `online_cloud_license?` defensively:
    # staging / dev environments simulating gitlab.com may ship with a
    # non-online-cloud license shape, and we want them routed to the online
    # branch rather than silently falling through to offline.
    class Resolver
      include ::Gitlab::Loggable
      include ::Gitlab::Utils::StrongMemoize

      INELIGIBLE = Entitlement.new(state: :ineligible).freeze

      MEMOIZATION_KEY = :secrets_management_entitlement

      # Rails.cache holds `Entitlement#to_h` and rebuilds it with `Entitlement.new(**hash)`, which
      # rejects unknown keys. Keying on the field list gives each code version its own entry, so
      # during a rolling deploy an old node never reads a hash shaped by a new one (or vice versa).
      ATTRIBUTES_CACHE_VERSION = Digest::SHA256.hexdigest(Entitlement.members.join(',')).first(8)

      # Where the served entitlement came from. `live` is CDot's own answer,
      # `lkg_stale` replays its last one, `fail_closed` is a denial we could not
      # attribute to CDot. Only the last two are logged -- the policy conditions
      # resolve on ordinary page renders, so logging `live` would move fleet log
      # volume for no diagnostic gain.
      SOURCES = %i[live lkg_stale fail_closed].freeze
      LOGGED_SOURCES = %i[lkg_stale fail_closed].freeze

      # CDot's "no billing vehicle right now" answers; their real meaning
      # depends on the /trials lifecycle state.
      DEFAULT_DENY_REASONS = %i[on_demand_disabled usage_not_allowed].freeze

      # Reasons both the client and the Entitlement contract express verbatim;
      # anything else is relabelled or fails closed in unmappable_block.
      PASSTHROUGH_REASONS = (BLOCKED_REASONS &
        ::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse::BLOCKED_REASONS).freeze

      # Sentry dedup window for unmapped-reason reports (see #report_unmapped_reason).
      UNMAPPED_REASON_REPORT_TTL = 6.hours

      # See the instance `cache_key` docs below for the axis rationale.
      def self.cache_key_for(namespace)
        if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          [MEMOIZATION_KEY, :saas, namespace&.id]
        else
          [MEMOIZATION_KEY, :self_managed]
        end
      end

      # Callers that change local intent state mid-request (add-on enrollment)
      # must drop every cache layer, or the memoized entitlement outlives the
      # change for the rest of the request (and the cache_ttl layer beyond it).
      # The last-known-good slot goes too: it would otherwise let a later
      # transport failure replay CDot's pre-change answer.
      def self.clear_cache(namespace)
        key = cache_key_for(namespace)

        ::Gitlab::SafeRequestStore.delete(key)
        delete_cached_attributes(namespace)
        LastKnownGoodStore.delete(key)
      end

      def self.delete_cached_attributes(namespace)
        # Pre-versioning nodes still read the bare key during a rolling deploy.
        # TODO: remove in 19.6, see https://gitlab.com/gitlab-org/gitlab/-/work_items/630675
        Rails.cache.delete(cache_key_for(namespace))
        Rails.cache.delete(attributes_cache_key_for(namespace))
      end

      # Only the Rails.cache layer is versioned: the request store never outlives one process
      # and the last-known-good store holds raw CDot responses, not this hash.
      def self.attributes_cache_key_for(namespace)
        [*cache_key_for(namespace), ATTRIBUTES_CACHE_VERSION]
      end

      # Pre-creates one series per source on first use: `lkg_stale` and
      # `fail_closed` are rare, and an absent series is indistinguishable from a
      # healthy silent one, so an alert on either would match nothing until the
      # moment it was needed.
      def self.resolutions_total
        @resolutions_total ||= ::Gitlab::Metrics
          .counter(:gitlab_secrets_manager_entitlement_resolutions_total,
            'Secrets Manager online entitlement resolutions by source')
          .tap { |counter| SOURCES.each { |source| counter.increment({ source: source.to_s }, 0) } }
      end

      def initialize(namespace, user: nil, http_timeout: nil, cache_ttl: nil, fresh: false)
        validate_namespace!(namespace)
        @namespace = namespace
        @user = user
        @http_timeout = http_timeout
        @cache_ttl = cache_ttl
        @fresh = fresh
      end

      # With `cache_ttl`, adds the same Rails.cache layer `resolve!` uses: a live resolution is
      # shared with any other resolver reading the same `cache_key` (e.g. a gate timeout followed
      # by this resolving live repairs the gate's own cache for the rest of the window). A
      # fail-closed `:ineligible` is never the thing that gets cached, only a genuine answer is.
      def resolve
        ::Gitlab::SafeRequestStore.fetch(cache_key) do
          next resolve_uncached unless @cache_ttl

          resolve_uncached_with_cache
        end
      end

      # Same resolution as `resolve`, but propagates failures instead of
      # failing closed to `:ineligible`. Nothing is cached when the block
      # raises, so a later `resolve` in the same request retries.
      # With `cache_ttl`, adds a Rails.cache layer on the same key, caching plain attributes (deploy-safe).
      def resolve!
        ::Gitlab::SafeRequestStore.fetch(cache_key) do
          next resolve_uncached! unless @cache_ttl

          cached_resolve!
        end
      end

      # Re-asks CDot past every cache for a user who changed billing consent in
      # the Customers Portal. Unlike `clear_cache`, nothing is deleted up front:
      # cached answers and the last-known-good slot are only ever replaced by a
      # newer CDot answer, so a failed refresh cannot remove the outage fallback.
      def refresh!
        entitlement = resolve_uncached!

        self.class.delete_cached_attributes(@namespace)
        ::Gitlab::SafeRequestStore.write(cache_key, entitlement)

        entitlement
      end

      private

      # Cache key reflects what actually varies the result.
      #
      # - SaaS: each top-level namespace has its own CDot-tracked entitlement
      #   (CDot keys by namespace_id), so the key includes `@namespace&.id`.
      # - Self-managed (online cloud or offline): entitlement is install-wide.
      #   Online cloud installs ask CDot per-instance (`/trials(instance_id)`)
      #   and offline installs read the instance-level AddOnPurchase mirror --
      #   either way, every namespace in the same request shares one entry.
      def cache_key
        self.class.cache_key_for(@namespace)
      end

      def attributes_cache_key
        self.class.attributes_cache_key_for(@namespace)
      end

      def validate_namespace!(namespace)
        return if namespace.nil?
        return if namespace.is_a?(::Group) && namespace.root?

        raise ArgumentError,
          "SecretsManagement::Entitlement.for expects a top-level Group or nil (got #{namespace.class})"
      end

      def resolve_uncached
        resolve_uncached!
      rescue StandardError => e
        fail_closed(e)
      end

      # Converts a raised resolution failure to the fail-closed default instead of propagating
      # it, like `resolve_uncached` does for the uncached path.
      def resolve_uncached_with_cache
        cached_resolve!
      rescue StandardError => e
        fail_closed(e)
      end

      # An exception from the block means `Rails.cache.fetch` writes nothing, so only a
      # genuine answer ever lands in the shared cache entry, never a fail-closed default.
      def cached_resolve!
        attributes = Rails.cache.fetch(attributes_cache_key, expires_in: @cache_ttl) { resolve_uncached!.to_h }
        Entitlement.new(**attributes)
      end

      def fail_closed(error)
        ::SecretsManagement::ThrottledErrorTracking.track_exception(
          error,
          throttle_key: :entitlement_fail_closed,
          issue_type: 'secrets_management_entitlement_fail_closed',
          gl_namespace_id: @namespace&.id
        )
        # exceptions_json.log prefixes every custom field with `extra.` and has
        # no `message` field, so this line is the searchable record; the report
        # above keeps the backtrace.
        track_resolution(:fail_closed, error: error)
        ineligible_entitlement
      end

      def resolve_uncached!
        license = ::License.current
        return INELIGIBLE if license.nil?

        # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- gitlab.com is its own routing axis; license shape alone isn't guaranteed in staging/dev
        # Unlike self-managed, SaaS has no instance-level entitlement, so a nil namespace has nothing to resolve.
        return INELIGIBLE if ::Gitlab.com? && @namespace.nil?

        # A trial subscription has no Premium/Ultimate base charge, so CDot can never deem it
        # eligible -- don't ask. SaaS trials ride on the namespace plan, not the license.
        return INELIGIBLE if !::Gitlab.com? && license.trial?

        if ::Gitlab.com? || license.online_cloud_license?
          resolve_online
        else
          resolve_offline
        end
        # rubocop:enable Gitlab/AvoidGitlabInstanceChecks
      end

      # Merges the two CDot responses: /consumers/resolve decides blocked
      # yes/no + reason, /trials supplies lifecycle state and quota counters.
      def resolve_online
        kwargs = cdot_identifier_kwargs
        kwargs[:timeout] = @http_timeout if @http_timeout
        kwargs[:fresh] = true if @fresh
        trial = ::Gitlab::SubscriptionPortal::Client.secrets_manager_trial(**kwargs)
        # /consumers/resolve decides per namespace (CDot keys the secrets_read
        # consumer by root namespace); user_id is only CDot audit metadata, so
        # the answer, and the cache key, are the same for every user.
        resolve = ::Gitlab::SubscriptionPortal::Client.secrets_manager_consumer_resolve(**kwargs, user_id: @user&.id)
        return with_beta_attributes(INELIGIBLE) unless trial && resolve

        entitlement = with_beta_attributes(map_cdot_response(trial, resolve))

        # After the merge, so a stored slot is always one that merged at least
        # once. Any explicit answer, deny included, replaces it, so a deny is
        # never delayed by the window.
        LastKnownGoodStore.write(cache_key, trial: trial, resolve: resolve)

        track_resolution(:live)
        entitlement
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        resolve_from_last_known_good(e)
      end

      # A denial needs an explicit answer from CDot, so only the client's UnavailableError
      # triggers the fallback.
      def resolve_from_last_known_good(error)
        # A refresh asks for CDot's current answer; replaying an old one would defeat it.
        raise error if @fresh
        raise error unless ::Feature.enabled?(:secrets_manager_entitlement_lkg_fallback, :instance)
        raise error unless error.is_a?(::Gitlab::SubscriptionPortal::SecretsManagerResponseError::UnavailableError)

        record = LastKnownGoodStore.read(cache_key)
        raise error unless record

        # The merge re-evaluates the subscription grace window against today and
        # re-reads the enrollment, so a grace window that lapsed
        # mid-outage is not extended. `trial.state` is the exception: the client
        # derives it at parse time from fields the slot does not keep, so
        # recomputing it here from `trial_expires_at` alone would read a stored
        # `:trial_eligible` (which has no expiry) as `:expired`, and the merge
        # maps that to `:paid`. An expiring trial therefore keeps serving
        # `:trial`, and its frozen credit counters, for the rest of the window.
        entitlement = with_beta_attributes(map_cdot_response(record.trial, record.resolve))
        # Read-only answers replay too. Callers that need direct reads or writes still check
        # them on the result, so the replay never grants more than the live answer would.
        raise error unless entitlement.permits_read?

        track_resolution(:lkg_stale, error: error, resolved_at: record.resolved_at)
        entitlement
      end

      # gitlab.com asks CDot per top-level namespace; self-managed online-cloud
      # asks CDot per instance. Routing already gated on
      # `License.current.online_cloud_license?` upstream, so we only need to
      # disambiguate SaaS from SM here.
      # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- per-namespace (SaaS) vs per-instance (SM) CDot identity
      def cdot_identifier_kwargs
        if ::Gitlab.com?
          { namespace_id: @namespace&.id }
        else
          { instance_id: ::Gitlab::CurrentSettings.uuid }
        end
      end
      # rubocop:enable Gitlab/AvoidGitlabInstanceChecks

      def map_cdot_response(trial, resolve)
        if resolve.blocked && !pre_trial_block?(trial, resolve)
          blocked_reason = blocked_reason_from(trial, resolve)

          return blocked_reason ? blocked_entitlement(trial, blocked_reason) : unmappable_block(trial, resolve)
        end

        case trial.state
        when :trial_eligible
          if add_on_requested?
            Entitlement.new(
              state: :paid,
              on_demand_enabled: trial.on_demand_enabled
            )
          else
            Entitlement.new(
              state: :trial_eligible,
              trial_expires_at: trial.trial_expires_at,
              on_demand_enabled: trial.on_demand_enabled
            )
          end
        when :trial
          Entitlement.new(
            state: :trial,
            trial_started_at: trial.trial_started_at,
            trial_expires_at: trial.trial_expires_at,
            credits_remaining: trial.credits_remaining,
            credits_total: trial.credits_total,
            on_demand_enabled: trial.on_demand_enabled
          )
        when :expired
          Entitlement.new(
            state: :paid,
            trial_started_at: trial.trial_started_at,
            trial_expires_at: trial.trial_expires_at,
            on_demand_enabled: trial.on_demand_enabled
          )
        when :ineligible
          # A never-trialled converter flips to :ineligible when the trial
          # offer sunsets on CDot; while /consumers/resolve still allows (and
          # bills), the group must stay paid -- parity with :expired above.
          if add_on_requested?
            Entitlement.new(
              state: :paid,
              on_demand_enabled: trial.on_demand_enabled
            )
          else
            INELIGIBLE
          end
        else
          raise ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse::Error,
            "Unhandled CDot trial state: #{trial.state.inspect}"
        end
      end

      # A default-deny answer for a trial-eligible namespace is the normal
      # pre-trial shape, not enforcement -- :blocked would hide the trial CTA.
      # Not for a stamped install: a never-trialled converter still reads as
      # :trial_eligible on /trials, so its default deny is consent withdrawn.
      def pre_trial_block?(trial, resolve)
        DEFAULT_DENY_REASONS.include?(resolve.blocked_reason) && trial.state == :trial_eligible && !add_on_requested?
      end

      # Paid add-on without a trial: CDot has no per-product paid signal
      # (opt_in_paid is account-wide), so the intent lives locally and
      # billability is CDot's live /consumers/resolve answer. Only consulted
      # on the unblocked branches of map_cdot_response, so a blocked answer
      # never turns into :paid. Keyed on the install like `beta_enrolled?`:
      # self-managed callers pass the root group (policies, CI) or nil
      # (instance mutations) and share one install-wide cache entry, so both
      # shapes must read the instance stamp.
      def add_on_requested?
        unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          return ::SecretsManagement::InstanceEnrollment.add_on_requested?
        end

        # A nil namespace on SaaS never gets here: resolve_uncached! returns INELIGIBLE first.
        ::SecretsManagement::NamespaceEnrollment.add_on_requested?(@namespace)
      end

      # Fails closed without raising so the parsed response stays cacheable.
      # Only usage_not_allowed (the expected plan-trial shape) is silent;
      # any other unmapped reason is reported as contract drift.
      def unmappable_block(trial, resolve)
        report_unmapped_reason(trial, resolve) unless resolve.blocked_reason == :usage_not_allowed

        INELIGIBLE
      end

      # The mapping re-runs on every uncached resolution (resolve! with
      # cache_ttl caches the mapped entitlement itself), so Sentry gets one
      # event per reason per window while Kibana keeps the full stream.
      def report_unmapped_reason(trial, resolve)
        error = ::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse::Error.new(
          "Unmapped CDot consumer-resolve blocked_reason: #{resolve.blocked_reason.inspect}"
        )

        ::SecretsManagement::ThrottledErrorTracking.track_exception(
          error,
          throttle_key: [:unmapped_block_reason, resolve.blocked_reason],
          ttl: UNMAPPED_REASON_REPORT_TTL,
          issue_type: 'secrets_management_entitlement_fail_closed',
          gl_namespace_id: @namespace&.id,
          trial_state: trial.state
        )
      end

      # Counts every online resolution by source, and logs the two that mean
      # something went wrong. `lkg_age_s` is the replayed slot's age, so
      # `WINDOW` minus it is what is left before the outage starts denying.
      # cdot_status is CDot's upstream status, so it avoids Labkit's `status` (this request's
      # own) and matches the client's error reports; nil unless `try` finds a status error.
      def track_resolution(source, error: nil, resolved_at: nil)
        self.class.resolutions_total.increment({ source: source.to_s })

        return unless LOGGED_SOURCES.include?(source)

        # labkit variant: the plain one emits `class`, which LabKit's field
        # standardization check reports as deprecated in favour of `class_name`.
        ::Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            message: 'Secrets Manager entitlement resolution',
            source: source.to_s,
            ::Labkit::Fields::GL_NAMESPACE_ID => @namespace&.id,
            cdot_error_class: error && (error.cause || error).class.name,
            cdot_status: error.try(:cdot_status),
            cdot_block_reason: error.try(:cdot_block_reason),
            lkg_age_s: resolved_at && (Time.current - resolved_at).to_f.round(6)
          ).compact
        )
      rescue StandardError => e
        # Runs inside the fail-closed rescue, so a raise here would turn a
        # denial into a 500. Still fails CI, where this re-raises.
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
      end

      # Error-swallowing fallback for the fail-closed rescue in
      # resolve_uncached, which has already logged the original error.
      # Must not be used under resolve! paths, where failures propagate.
      def ineligible_entitlement
        with_beta_attributes(INELIGIBLE)
      rescue StandardError
        INELIGIBLE
      end

      # Attaches beta fields to the entitlement. The enrollment DB lookup
      # only runs for states where the beta window can open, keeping the
      # query off the hot authorization path for converted customers.
      def with_beta_attributes(entitlement)
        Entitlement.new(
          **entitlement.to_h,
          beta_program_ended: true,
          beta_window_eligible: BETA_WINDOW_STATES.include?(entitlement.state) && beta_enrolled?
        )
      end

      # SaaS reads the `beta` marker on the namespace enrollment row; self-managed
      # reads the instance-wide marker on the application settings, matching the
      # install-wide cache key above.
      def beta_enrolled?
        unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          return ::SecretsManagement::InstanceEnrollment.beta_enrolled?
        end

        return false if @namespace.nil?

        ::SecretsManagement::NamespaceEnrollment.beta_enrolled?(@namespace)
      end

      def blocked_entitlement(trial, blocked_reason)
        Entitlement.new(
          state: :blocked,
          blocked_reason: blocked_reason,
          grace_period_end_date: grace_period_end_date(blocked_reason),
          trial_started_at: trial.trial_started_at,
          trial_expires_at: trial.trial_expires_at,
          credits_remaining: trial.credits_remaining,
          credits_total: trial.credits_total,
          on_demand_enabled: trial.on_demand_enabled
        )
      end

      # Last inclusive day of the `:grace` window, mirroring the `<=` in
      # grace_window_reason. Relies on grace_anchor_date being memoized so the
      # anchor is not queried a second time.
      def grace_period_end_date(blocked_reason)
        return unless blocked_reason == :grace

        anchor = grace_anchor_date
        anchor + GRACE_DAYS if anchor
      end

      # Relabels default-deny reasons by trial lifecycle. Returns nil when no
      # Entitlement blocked_reason applies; the caller fails closed to :ineligible.
      def blocked_reason_from(trial, resolve)
        reason = resolve.blocked_reason

        return :credits_exhausted if DEFAULT_DENY_REASONS.include?(reason) && trial.state == :trial
        return :trial_expired if DEFAULT_DENY_REASONS.include?(reason) && trial.state == :expired
        # A converter's default deny is withdrawn consent, whatever wording CDot uses.
        return :on_demand_disabled if DEFAULT_DENY_REASONS.include?(reason) && add_on_requested?
        return grace_window_reason if reason == :no_billable_source_error

        reason if PASSTHROUGH_REASONS.include?(reason)
      end

      def grace_window_reason
        end_date = grace_anchor_date

        return :subscription_grace_period_expired if end_date.nil?

        Date.current <= end_date + GRACE_DAYS ? :grace : :subscription_grace_period_expired
      end

      def grace_anchor_date
        if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          subscription = @namespace&.gitlab_subscription
          subscription.end_date if subscription&.has_a_paid_hosted_plan?
        else
          self_managed_grace_anchor_date
        end
      end
      strong_memoize_attr :grace_anchor_date

      # CDot only generates the add-on for offline licenses, and a sync without it only expires the
      # row, so take the later of the mirror and the online license term (the SaaS end_date counterpart).
      # Both dates are exclusive; -1 day matches end_date's inclusive semantics.
      def self_managed_grace_anchor_date
        mirror_expires_on = ::GitlabSubscriptions::AddOnPurchase
          .for_secrets_manager
          .for_self_managed
          .non_trial
          .maximum(:expires_on)

        expires_on = [mirror_expires_on, online_license_expires_on].compact.max

        return unless expires_on

        expires_on - 1.day
      end

      def online_license_expires_on
        license = ::License.current
        return unless license.online_cloud_license?

        license.expires_at
      end

      # Offline (air-gapped) self-managed installs have no CDot connection,
      # so the local AddOnPurchase mirror (populated from the license payload)
      # is the only signal. Trial state, on-demand billing, grace periods
      # cannot be observed here -- only `:offline_paid` and
      # `:blocked + :subscription_grace_period_expired` are reachable.
      # Flex licenses entitle through flex_offline; secrets_manager is co-provisioned on
      # them only transitionally, and is all a non-Flex license carries.
      def resolve_offline
        add_on_names = ::GitlabSubscriptions::AddOnPurchase
          .by_add_on_name(%i[secrets_manager flex_offline])
          .for_self_managed
          .active
          .uniq_add_on_names

        if add_on_names.empty?
          return Entitlement.new(state: :blocked, blocked_reason: :subscription_grace_period_expired)
        end

        Entitlement.new(state: :offline_paid, offline_flex_license: add_on_names.include?('flex_offline'))
      end
    end
  end
end
