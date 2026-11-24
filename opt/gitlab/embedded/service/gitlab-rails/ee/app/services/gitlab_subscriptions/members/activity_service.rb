# frozen_string_literal: true

module GitlabSubscriptions
  module Members
    class ActivityService
      include ExclusiveLeaseGuard

      LEASE_KEY_FORMAT = "gitlab_subscriptions:members_activity_event:%s:%s"
      LEASE_TIMEOUT = 24.hours.to_i

      def self.lease_taken?(namespace_id, user_id)
        Gitlab::ExclusiveLease.get_uuid(format(LEASE_KEY_FORMAT, namespace_id, user_id))
      end

      def initialize(user, namespace)
        @user = user
        @namespace = namespace&.root_ancestor
      end

      def execute
        return ServiceResponse.error(message: 'Invalid params') unless namespace&.group_namespace? && user

        response = try_obtain_lease do
          if seat_assignment
            seat_assignment.update!(last_activity_on: Time.current)
          else
            break unless user_is_a_member?

            GitlabSubscriptions::SeatAssignment.create!(
              namespace: namespace,
              user: user,
              last_activity_on: Time.current,
              organization_id: namespace.organization_id
            )
          end
        end

        if response
          ServiceResponse.success(message: 'Member activity tracked')
        else
          ServiceResponse.error(message: 'Member activity could not be tracked')
        end
      end

      private

      attr_reader :user, :namespace

      def lease_timeout
        LEASE_TIMEOUT
      end

      # Used by ExclusiveLeaseGuard
      # do not update the record, if it has been already updated within the last lease_timeout
      def lease_release?
        false
      end

      def lease_key
        format(LEASE_KEY_FORMAT, namespace.id, user.id)
      end

      def seat_assignment
        @seat_assignment ||= GitlabSubscriptions::SeatAssignment.find_by_namespace_and_user(namespace, user)
      end

      def user_is_a_member?
        ::Member.in_hierarchy(namespace).with_user(user).exists?
      end
    end
  end
end
