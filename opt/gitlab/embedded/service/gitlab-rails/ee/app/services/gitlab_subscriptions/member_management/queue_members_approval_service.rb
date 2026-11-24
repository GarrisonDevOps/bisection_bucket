# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class QueueMembersApprovalService < BaseService
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

      BATCH_SIZE = 30

      def initialize(non_billable_to_billable_users, current_user, params = {})
        @source_namespace = params[:source_namespace]
        @current_user = current_user
        @non_billable_to_billable_users = non_billable_to_billable_users
        @existing_members_hash = params[:existing_members_hash]
        @params = params
      end

      def execute
        return success if non_billable_to_billable_users.empty?

        users_queued_for_approval = queue_users_for_approval
        success(users_queued_for_approval: users_queued_for_approval)
      rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique
        error
      end

      private

      attr_accessor :non_billable_to_billable_users, :existing_members_hash, :source_namespace

      def success(users_queued_for_approval: [])
        ServiceResponse.success(payload: {
          users_queued_for_approval: users_queued_for_approval
        })
      end

      def error
        ServiceResponse.error(message: "Invalid record while enqueuing users for approval")
      end

      def queue_users_for_approval
        # `run_after_commit` blocks are evaluated in the approval's context, so capture the organization here.
        organization = source_namespace.organization

        non_billable_to_billable_users.each_slice(BATCH_SIZE).flat_map do |user_batch|
          ::GitlabSubscriptions::MemberManagement::MemberApproval.transaction do
            approvals = []

            user_batch.map do |user|
              member = existing_members_hash[user.id]
              attributes = {
                new_access_level: params[:access_level],
                member_role_id: params[:member_role_id],
                requested_by: current_user,
                member: member,
                old_access_level: member&.access_level,
                metadata: params.slice(:access_level, :expires_at, :member_role_id)
              }

              approval = ::GitlabSubscriptions::MemberManagement::MemberApproval.create_or_update_pending_approval(
                user, source_namespace, attributes
              )

              approvals << approval

              approval.run_after_commit do
                payload = Gitlab::DataBuilder::MemberApprovalBuilder.build(event: :queued, approval: approval)
                SystemHooksService.new.execute_hooks(
                  payload, :member_approval_hooks, organization: organization
                )
              end
            end

            approvals
          end
        end
      end
    end
  end
end
