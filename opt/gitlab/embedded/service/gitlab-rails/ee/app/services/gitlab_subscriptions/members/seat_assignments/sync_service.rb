# frozen_string_literal: true

module GitlabSubscriptions
  module Members
    module SeatAssignments
      class SyncService
        BATCH_SIZE = 500

        def initialize(user_ids, root_namespace)
          @user_ids = user_ids.compact.uniq
          @root_namespace = root_namespace
        end

        def execute
          return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          return invalid_namespace_error unless root_group_namespace?

          user_ids.each_slice(BATCH_SIZE) do |batch_user_ids|
            seats_to_upsert = seat_type_mappings(batch_user_ids)

            upsert_seat_assignments(seats_to_upsert) if seats_to_upsert.any?
          end

          ServiceResponse.success
        end

        private

        attr_reader :user_ids, :root_namespace

        def upsert_seat_assignments(seats_to_upsert)
          seat_assignments = seats_to_upsert.map { |user_id, seat_type| seat_assignment(user_id, seat_type) }

          GitlabSubscriptions::SeatAssignment.upsert_all(seat_assignments, unique_by: [:namespace_id, :user_id])
        end

        def seat_type_mappings(user_ids)
          GitlabSubscriptions::SeatTypeCalculator.bulk_execute(user_ids, root_namespace).compact
        end

        def seat_assignment(user_id, seat_type)
          {
            namespace_id: root_namespace.id,
            user_id: user_id,
            seat_type: seat_type,
            organization_id: root_namespace.organization_id
          }
        end

        def root_group_namespace?
          root_namespace.group_namespace? && root_namespace.root?
        end

        def invalid_namespace_error
          ServiceResponse.error(message: 'Seat assignments require a root group namespace on GitLab.com')
        end
      end
    end
  end
end
