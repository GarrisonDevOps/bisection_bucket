# frozen_string_literal: true

module Members
  module UnassignIssuables
    class BaseService
      attr_reader :user, :entity, :requesting_user

      # @param [User] user user whose membership is being deleted from entity
      # @param [Group, Project] entity
      # @param [User] requesting_user user who initiated the membership deletion of `user`
      def initialize(user, entity, requesting_user)
        @user = user
        @entity = entity
        @requesting_user = requesting_user
      end

      def execute
        raise ArgumentError, 'requesting_user must be given' unless requesting_user
        return ServiceResponse.success unless entity && user

        processed = 0
        skipped = 0
        still_assigned = 0

        assignees.each_batch(column: id_column) do |batch|
          batch.with_issuables_for_update.each do |assignee|
            if unassign(issuable_for(assignee))
              processed += 1
            else
              skipped += 1
            end
          end

          # An update can run and still leave the user assigned, for example without permission.
          still_assigned += batch.count
        end

        user.invalidate_cache_counts

        ServiceResponse.success(payload: payload(processed:, skipped:, still_assigned:))
      end

      private

      # @return [Boolean] false when the issuable is gone, or was removed before the update saved
      def unassign(issuable)
        return false unless issuable

        save_assignees(issuable, remaining_assignee_ids(issuable))
        true
      rescue ActiveRecord::StaleObjectError
        # The issuable can be removed before the update service saves it. Continue with the next one.
        false
      end

      # Read right before the update, as a list preloaded with the batch could drop assignees added since.
      def remaining_assignee_ids(issuable)
        issuable.assignees.map(&:id) - [user.id]
      end

      def assignees
        assignee_class.for_assignee(user).in_projects(project_ids)
      end

      def project_ids
        @project_ids ||= entity.is_a?(Group) ? entity.all_projects.select(:id) : [entity.id]
      end

      def assignee_class
        raise NotImplementedError
      end

      def id_column
        raise NotImplementedError
      end

      def payload(processed:, skipped:, still_assigned:)
        raise NotImplementedError
      end

      def issuable_for(_assignee)
        raise NotImplementedError
      end

      def save_assignees(_issuable, _assignee_ids)
        raise NotImplementedError
      end
    end
  end
end
