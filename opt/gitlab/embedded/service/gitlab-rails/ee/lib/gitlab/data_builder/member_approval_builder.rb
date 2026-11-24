# frozen_string_literal: true

module Gitlab
  module DataBuilder
    module MemberApprovalBuilder
      extend self

      def build(event:, reviewed_by: nil, user: nil, status: nil, failed_approvals: [], approval: nil, reviewed_at: nil)
        case event
        when :queued
          raise ArgumentError, "Need to pass approval object to build queued event." unless approval.present?

          build_queued_event(approval)
        when :approved
          build_approved_event(reviewed_by, user, failed_approvals, status, reviewed_at)
        when :denied
          build_denied_event(reviewed_by, user, status, reviewed_at)
        end
      end

      private

      def build_queued_event(approval)
        {
          object_kind: 'gitlab_subscription_member_approval',
          object_attributes: approval.hook_attrs,
          action: 'enqueue',
          user_id: approval.user_id,
          requested_by_user_id: approval.requested_by_id,
          promotion_namespace_id: approval.member_namespace_id,
          created_at: approval.created_at&.xmlschema,
          updated_at: approval.updated_at&.xmlschema
        }
      end

      def build_approved_event(reviewed_by, user, failed_approvals, status, reviewed_at)
        {
          object_kind: 'gitlab_subscription_member_approvals',
          action: 'approve',
          object_attributes: {
            promotion_request_ids_that_failed_to_apply: failed_approvals.map(&:id),
            status: status
          },
          reviewed_by_user_id: reviewed_by&.id,
          user_id: user.id,
          updated_at: reviewed_at&.xmlschema
        }
      end

      def build_denied_event(reviewed_by, user, status, reviewed_at)
        {
          object_kind: 'gitlab_subscription_member_approvals',
          action: 'deny',
          object_attributes: {
            status: status
          },
          reviewed_by_user_id: reviewed_by&.id,
          user_id: user.id,
          updated_at: reviewed_at&.xmlschema
        }
      end
    end
  end
end
