# frozen_string_literal: true

module Analytics
  class GroupActivityCalculator
    include Gitlab::Loggable

    RECENT_DURATION = 30.days
    RECENT_COUNT_LIMIT = 1000
    CACHE_OPTIONS = { raw: false, expires_in: 24.hours }.freeze
    TOO_LARGE = 'too_large'
    TOO_LARGE_CACHE_OPTIONS = { raw: false, expires_in: 1.hour }.freeze
    STATEMENT_TIMEOUT_MS = 4500

    def initialize(group, current_user)
      @group = group
      @current_user = current_user
      @too_large_types = Set.new
    end

    def issues_count
      @issues_count ||= fetch_cached(:issues, Issue) do
        IssuesFinder.new(@current_user, issuable_params).execute.limit(RECENT_COUNT_LIMIT).without_order.count
      end
    end

    def merge_requests_count
      @merge_requests_count ||= fetch_cached(:merge_requests, MergeRequest) do
        MergeRequestsFinder.new(@current_user, issuable_params).execute.limit(RECENT_COUNT_LIMIT).without_order.count
      end
    end

    def new_members_count
      @new_members_count ||= fetch_cached(:new_members, Member) do
        GroupMembersFinder.new(
          @group,
          @current_user,
          params: { created_after: RECENT_DURATION.ago }
        ).execute(include_relations: [:direct, :descendants]).limit(RECENT_COUNT_LIMIT).without_order.count
      end
    end

    def too_large?(type)
      # Grape evaluates exposure conditions before values, so load the count first
      case type
      when :issues then issues_count
      when :merge_requests then merge_requests_count
      when :new_members then new_members_count
      else raise ArgumentError, "unknown group activity type: #{type}"
      end

      @too_large_types.include?(type)
    end

    private

    def issuable_params
      { group_id: @group.id,
        state: 'all',
        created_after: RECENT_DURATION.ago,
        include_subgroups: true,
        attempt_group_search_optimizations: true,
        attempt_project_search_optimizations: true }
    end

    def fetch_cached(type, klass, &block)
      result =
        if Feature.enabled?(:group_activity_fast_count_timeout, @group.root_ancestor)
          fetch_with_statement_timeout(type, klass, &block)
        else
          Rails.cache.fetch(cache_key(type), CACHE_OPTIONS) { use_replicas(klass, &block) }
        end

      return result.to_i unless result == TOO_LARGE

      @too_large_types << type
      RECENT_COUNT_LIMIT
    end

    def fetch_with_statement_timeout(type, klass, &block)
      result = Rails.cache.fetch(cache_key(type), CACHE_OPTIONS) do
        use_replicas(klass) { with_replica_statement_timeout(klass, &block) }
      end

      track_too_large(type, 'cache') if result == TOO_LARGE
      result
    rescue ActiveRecord::QueryCanceled => e # rubocop:disable Database/RescueQueryCanceled -- cache the timeout so the next request does not rerun the same query
      Gitlab::ErrorTracking.log_exception(e, { Labkit::Fields::GL_NAMESPACE_ID => @group.id, count_type: type })
      Rails.cache.write(cache_key(type), TOO_LARGE, TOO_LARGE_CACHE_OPTIONS)
      track_too_large(type, 'timeout')
      TOO_LARGE
    end

    # The counter is the alertable aggregate. Only a fresh timeout is logged: a cached result is
    # served on every page view until it expires, and its group is already in the timeout line.
    def track_too_large(type, source)
      too_large_counter.increment(count_type: type.to_s, source: source)
      return unless source == 'timeout'

      Gitlab::AppJsonLogger.info(build_structured_payload_labkit(
        Labkit::Fields::LOG_MESSAGE => 'Group activity count too large',
        Labkit::Fields::GL_NAMESPACE_ID => @group.id,
        Labkit::Fields::GL_ROOT_NAMESPACE_ID => @group.root_ancestor.id,
        count_type: type.to_s,
        source: source
      ))
    end

    def too_large_counter
      Gitlab::Metrics.counter(
        :gitlab_group_activity_count_too_large_total,
        'Group activity counts returned as too large instead of a number'
      )
    end

    def use_replicas(klass, &block)
      ::Gitlab::Database::LoadBalancing::SessionMap
        .current(klass.load_balancer)
        .use_replicas_for_read_queries(&block)
    end

    # Not ApplicationRecord.with_fast_read_statement_timeout: when the session sticks to the primary, it
    # opens its transaction there while the count still reads from a replica, so the timeout never applies.
    def with_replica_statement_timeout(klass)
      klass.load_balancer.read do |connection|
        connection.transaction do
          connection.exec_query("SET LOCAL statement_timeout = #{STATEMENT_TIMEOUT_MS}")

          yield
        end
      end
    end

    def cache_key(type)
      ['groups', "recent_30d_#{type}_count", @group.id, @current_user.id]
    end
  end
end
