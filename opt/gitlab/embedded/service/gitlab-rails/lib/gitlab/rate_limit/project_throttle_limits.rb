# frozen_string_literal: true

module Gitlab
  module RateLimit
    # Per-project overrides for the Git HTTP and Git-LFS request thresholds,
    # enforced by the Labkit rules through Gitlab::Throttle.project_git_limit.
    #
    # The whole override set is held in the process, not read per request: a Git
    # request for a project with no override must not cost more than it does
    # today. Gitlab::ProcessMemoryCache is deliberately not used here: its
    # DupCoder Marshal-dumps and reloads the value on every read, inside the
    # store's global monitor, which measured ~357us per read at the row cap.
    class ProjectThrottleLimits
      CACHE_TTL = 1.minute

      # Memo slot on the Rack env: the three per-throttle override facts resolve
      # the same request, and the route regex is the expensive part of a throttle
      # evaluation.
      ENV_KEY = 'gitlab.rate_limit.git_full_path'

      # Anchored on both sides of `.git`, or /group/awesome.github/info/refs would
      # resolve to group/awesome. Named so the numbered groups inside the shared
      # route regex stay out of the way.
      PROJECT_PATH_REGEX = %r{\A/(?<full_path>#{::Gitlab::PathRegex.repository_route_regex})\.git(?=/|\z)}

      MUTEX = Mutex.new

      class << self
        # The effective threshold for an override key the Labkit rule already
        # matched on, clamped to the default.
        def limit_for_key(throttle, key, default:)
          value = overrides[key]&.last&.[](throttle)
          return default if value.nil?

          [value, default].min
        end

        # The segment to append to this throttle's counter key, or nil. Scoped to the
        # throttle: a project overriding only one throttle keeps sharing the instance-wide
        # counter for the others, or they would gain a second full-size bucket.
        def override_key_for(throttle, path:, env: nil)
          matched_path(path, env: env) { |limits| limits.key?(throttle) }
        end

        # Test hook. Per-process by construction, so this cannot invalidate other
        # processes; CACHE_TTL is the real propagation bound.
        def expire!
          MUTEX.synchronize { @cache = nil }
        end

        private

        # The project's current path, whichever of its paths was requested, so pre-rename
        # paths share one counter. An exact match wins before the parent fallback, since
        # a project may be named "foo.wiki" when no sibling "foo" exists.
        def matched_path(path, env:)
          return if overrides.empty?

          full_path = full_path_from(path, env: env)
          return unless full_path

          entry = overrides[full_path]
          return entry.first if entry && yield(entry.last)

          parent = parent_repository_path(full_path)
          return unless parent

          parent_entry = overrides[parent]
          parent_entry.first if parent_entry && yield(parent_entry.last)
        end

        def parent_repository_path(full_path)
          suffix = sibling_repository_suffixes.find { |candidate| full_path.end_with?(candidate) }
          full_path.delete_suffix(suffix) if suffix
        end

        # Wiki and design repositories hang off the project's path, so its override covers
        # them too; derived from GlRepository so a new type can't reopen that gap. Snippet
        # repositories stay on the instance limit, as in Gitlab::RateLimit::TargetKey.
        def sibling_repository_suffixes
          @sibling_repository_suffixes ||= ::Gitlab::GlRepository.types.values
            .filter_map { |type| type.path_suffix.presence }
            .freeze
        end

        def full_path_from(path, env:)
          return env[ENV_KEY] if env&.key?(ENV_KEY)

          full_path = extract_full_path(path)
          env[ENV_KEY] = full_path if env
          full_path
        end

        # Git HTTP is also routed under /o/:organization_path, and PROJECT_PATH_REGEX is
        # anchored, so strip that prefix or an org-scoped clone falls back to the instance
        # limit. The helper uses routing's own regex, so it accepts exactly the routed paths.
        def extract_full_path(path)
          match = PROJECT_PATH_REGEX.match(::Gitlab::Routing::OrganizationsHelper.unscoped_path(path))
          return unless match

          match[:full_path].downcase
        end

        # Returned frozen and by reference: this is read several times per Git
        # request, so it must not copy.
        def overrides
          cached = @cache
          return cached[:value] if cached && cached[:expires_at] > monotonic_time

          refresh(cached)
        end

        # Single-flight: losing threads serve the expired set instead of queueing behind
        # the ~160ms refresh at the row ceiling. One TTL of staleness bounds a throttle no
        # worse than the TTL already does.
        def refresh(stale)
          unless MUTEX.try_lock
            # Nothing to serve before the first load, so that one wait is unavoidable.
            return stale[:value] if stale

            MUTEX.lock # rubocop:disable CodeReuse/ActiveRecord -- Mutex#lock, not ActiveRecord's
          end

          begin
            now = monotonic_time
            cached = @cache
            return cached[:value] if cached && cached[:expires_at] > now

            value = load_overrides.freeze
            @cache = { value: value, expires_at: now + CACHE_TTL }
            value
          ensure
            MUTEX.unlock
          end
        end

        # Fails open: a throttle that cannot read its overrides falls back to the
        # instance default rather than taking Git over HTTP down with it.
        def load_overrides
          return {} unless ::Feature.enabled?(:project_git_throttle_overrides, :instance)

          ProjectSetting.git_throttle_overrides_by_full_path
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
          {}
        end

        def monotonic_time
          ::Gitlab::Metrics::System.monotonic_time
        end
      end
    end
  end
end
