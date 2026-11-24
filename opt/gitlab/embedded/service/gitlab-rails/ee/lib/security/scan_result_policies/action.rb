# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class Action
      def initialize(action)
        @action = action || {}
      end

      def type
        action[:type]
      end

      def type_require_approval?
        type == 'require_approval'
      end

      def type_send_bot_message?
        type == 'send_bot_message'
      end

      def approvals_required
        action[:approvals_required]
      end

      def enabled
        action[:enabled]
      end

      def internal?
        action[:visibility] == 'internal'
      end

      def user_approvers
        action[:user_approvers] || []
      end

      def user_approvers_ids
        action[:user_approvers_ids] || []
      end

      def group_approvers
        action[:group_approvers] || []
      end

      def group_approvers_ids
        action[:group_approvers_ids] || []
      end

      def role_approvers
        action[:role_approvers] || []
      end

      private

      attr_reader :action
    end
  end
end
