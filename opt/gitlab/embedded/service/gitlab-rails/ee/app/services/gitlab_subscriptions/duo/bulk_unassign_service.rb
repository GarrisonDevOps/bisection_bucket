# frozen_string_literal: true

module GitlabSubscriptions
  module Duo
    class BulkUnassignService < BaseService
      NO_ASSIGNMENTS_FOUND = 'NO_ASSIGNMENTS_FOUND'

      def initialize(add_on_purchase:, user_ids:)
        @add_on_purchase = add_on_purchase
        @user_ids = user_ids
      end

      def execute
        assignments = add_on_purchase.assigned_users.for_user_ids(user_ids)

        return handle_error(NO_ASSIGNMENTS_FOUND) unless assignments.any?

        delete_assignments!(assignments)

        handle_success(User.id_in(user_ids))
      end

      private

      attr_reader :add_on_purchase, :user_ids

      def delete_assignments!(assignments)
        assignments.delete_all
      end

      def handle_error(error_message)
        Gitlab::AppLogger.error(log_events(type: 'error', payload: { errors: error_message }))
        ServiceResponse.error(message: error_message)
      end

      def handle_success(users)
        Gitlab::AppLogger.info(log_events(type: 'success', payload: { users: user_ids }))
        ServiceResponse.success(payload: { users: users })
      end

      def log_events(type:, payload:)
        {
          add_on_purchase_id: add_on_purchase.id,
          message: 'Duo Bulk User Unassignment',
          response_type: type,
          payload: payload
        }
      end
    end
  end
end
