# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    module SeatAwareProvisioning
      AccessLevelAdjustment = Struct.new(:access_level, :adjusted) do
        def adjusted?
          adjusted
        end
      end

      # User IDs are date-bucketed with a 72-hour TTL to enable day-over-day comparison
      # of users affected by the Minimal Access role adjustment. Consumed by a daily
      # cron job that sends a notification when the set of affected users has changed
      SEAT_AWARE_PROVISIONING_CACHE_PERIOD = 72.hours

      SEAT_AWARE_PROVISIONING_ROOT_GROUPS_CACHE_KEY = 'seat_aware_provisioning:group:{%{date}}'
      SEAT_AWARE_PROVISIONING_USERS_CACHE_KEY = 'seat_aware_provisioning:group:%{root_namespace_id}:{%{date}}'
      SEAT_AWARE_PROVISIONING_INSTANCE_CACHE_KEY = 'seat_aware_provisioning:instance:{%{date}}'
      SEAT_AWARE_PROVISIONING_INSTANCE_DISMISSED_COUNT_CACHE_KEY =
        'seat_aware_provisioning:instance:dismissed_count:%{user_id}:{%{date}}'
      SEAT_AWARE_PROVISIONING_GROUP_DISMISSED_COUNT_CACHE_KEY =
        'seat_aware_provisioning:group:{%{root_namespace_id}}:dismissed_count:%{user_id}:%{date}'

      def self.instance_affected_users_count
        with_redis(default: 0) do |redis|
          redis.scard(format(SEAT_AWARE_PROVISIONING_INSTANCE_CACHE_KEY, date: Date.current.iso8601))
        end
      end

      def self.record_instance_count_at_dismissal(user)
        with_redis do |redis|
          redis.set(dismissed_count_cache_key(user), instance_affected_users_count, ex: 24.hours)
        end
      end

      def self.instance_count_at_last_dismissal(user)
        with_redis(default: 0) do |redis|
          redis.get(dismissed_count_cache_key(user)).to_i
        end
      end

      def self.group_affected_users_count(group)
        with_redis(default: 0) do |redis|
          redis.scard(format(SEAT_AWARE_PROVISIONING_USERS_CACHE_KEY,
            root_namespace_id: group.id,
            date: Date.current.iso8601
          ))
        end
      end

      def self.record_group_count_at_dismissal(group, user)
        with_redis(default: 0) do |redis|
          redis.set(
            group_dismissed_count_cache_key(group, user),
            group_affected_users_count(group),
            ex: 24.hours
          )
        end
      end

      def self.group_count_at_last_dismissal(group, user)
        with_redis(default: 0) do |redis|
          redis.get(group_dismissed_count_cache_key(group, user)).to_i
        end
      end

      private_class_method def self.dismissed_count_cache_key(user)
        format(
          SEAT_AWARE_PROVISIONING_INSTANCE_DISMISSED_COUNT_CACHE_KEY,
          user_id: user.id,
          date: Date.current.iso8601
        )
      end

      private_class_method def self.group_dismissed_count_cache_key(group, user)
        format(
          SEAT_AWARE_PROVISIONING_GROUP_DISMISSED_COUNT_CACHE_KEY,
          root_namespace_id: group.id,
          user_id: user.id,
          date: Date.current.iso8601
        )
      end

      private_class_method def self.with_redis(default: nil)
        ::Gitlab::Redis::SharedState.with do |redis|
          yield redis
        end
      rescue ::Redis::BaseError => e
        ::Gitlab::ErrorTracking.log_exception(e)
        default
      end

      def calculate_adjusted_access_level(source, invitee, requested_access_level, extra = {})
        adjusted_access_level = adjust_access_level_for_seat_availability(source, invitee, requested_access_level)
        role_adjusted = adjusted_access_level != requested_access_level

        if role_adjusted
          log_bso_access_level_adjustment(source, invitee, requested_access_level, adjusted_access_level, extra)
        end

        AccessLevelAdjustment.new(adjusted_access_level, role_adjusted)
      end

      def track_and_audit_minimal_access_provisioning(group, member, requested_access_level, extra = {})
        track_minimal_access_provisioning(group.root_ancestor, member&.user_id)
        audit_minimal_access_role_adjustment(group, member, requested_access_level, extra)
      end

      def format_users_cache_key(root_namespace_id, date)
        format(
          SEAT_AWARE_PROVISIONING_USERS_CACHE_KEY,
          root_namespace_id: root_namespace_id,
          date: date
        )
      end

      def format_instance_cache_key(date)
        format(
          SEAT_AWARE_PROVISIONING_INSTANCE_CACHE_KEY,
          date: date
        )
      end

      def format_root_groups_cache_key(date)
        format(
          SEAT_AWARE_PROVISIONING_ROOT_GROUPS_CACHE_KEY,
          date: date
        )
      end

      private

      def track_minimal_access_provisioning(root_namespace, user_identifier)
        return unless user_identifier

        if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          track_namespace_provisioning_event(root_namespace, user_identifier)
        else
          track_instance_provisioning_event(user_identifier)
        end
      end

      def audit_minimal_access_role_adjustment(group, member, requested_access_level, extra = {})
        return unless member

        audit_context = {
          name: 'group_minimal_access_role_adjusted_seat_limit',
          author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: group,
          target: member.user,
          message: "Assigned Minimal Access due to seat limit with restricted access.",
          additional_details: {
            member_id: member.id,
            user_id: member.user_id,
            user_state: member.user&.state,
            requested_access_level: requested_access_level
          }.merge(extra)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def adjust_access_level_for_seat_availability(source, invitee, desired_access_level)
        return desired_access_level unless apply_bso_adjustment?(source)
        return desired_access_level if seats_available_for_desired_access?(source, invitee, desired_access_level)

        ::Gitlab::Access::MINIMAL_ACCESS
      end

      def apply_bso_adjustment?(source)
        ::GitlabSubscriptions::MemberManagement::BlockSeatOverages.block_seat_overages?(source)
      end

      def seats_available_for_desired_access?(source, invitee, access_level)
        user_identifier = invitee.is_a?(User) ? invitee.id : invitee

        ::GitlabSubscriptions::MemberManagement::BlockSeatOverages.seats_available_for?(
          source, [user_identifier], access_level, nil
        )
      end

      def log_bso_access_level_adjustment(source, invitee, requested_access_level, adjusted_access_level, extra = {})
        user = invitee.is_a?(User) ? invitee : nil

        log_data = {
          message: 'Group membership access level adjusted due to BSO seat limits',
          group_id: source.id,
          group_path: source.full_path,
          user_id: user&.id,
          requested_access_level: requested_access_level,
          adjusted_access_level: adjusted_access_level
        }.merge(extra)

        ::Gitlab::AppLogger.info(log_data)
      end

      def track_namespace_provisioning_event(root_namespace, user_identifier)
        ::Gitlab::Redis::SharedState.with do |redis|
          redis.pipelined do |p|
            p.sadd(format_root_groups_cache_key(current_date), root_namespace.id.to_s)
            p.expire(format_root_groups_cache_key(current_date), SEAT_AWARE_PROVISIONING_CACHE_PERIOD)

            p.sadd(format_users_cache_key(root_namespace.id, current_date), user_identifier.to_s)
            p.expire(format_users_cache_key(root_namespace.id, current_date), SEAT_AWARE_PROVISIONING_CACHE_PERIOD)
          end
        end
      rescue ::Redis::BaseError => e
        ::Gitlab::ErrorTracking.log_exception(e)
      end

      def track_instance_provisioning_event(user_identifier)
        ::Gitlab::Redis::SharedState.with do |redis|
          redis.pipelined do |p|
            p.sadd(format_instance_cache_key(current_date), user_identifier.to_s)
            p.expire(format_instance_cache_key(current_date), SEAT_AWARE_PROVISIONING_CACHE_PERIOD)
          end
        end
      rescue ::Redis::BaseError => e
        ::Gitlab::ErrorTracking.log_exception(e)
      end

      def current_date
        @current_date ||= Date.current.iso8601
      end
    end
  end
end
