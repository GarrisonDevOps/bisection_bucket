# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MemberApproval < ApplicationRecord
      include Presentable
      include AfterCommitQueue

      self.table_name = 'member_approvals'

      enum :status, { pending: 0, approved: 1, denied: 2 }

      belongs_to :user
      belongs_to :member, optional: true
      belongs_to :member_namespace, class_name: 'Namespace'
      belongs_to :member_role, class_name: 'MemberRole', optional: true
      belongs_to :requested_by, inverse_of: :requested_member_approvals, class_name: 'User', optional: true
      belongs_to :reviewed_by, inverse_of: :reviewed_member_approvals, class_name: 'User', optional: true

      validates :new_access_level, presence: true
      validates :user, presence: true
      validates :member_namespace, presence: true
      validates :metadata, json_schema: { filename: "members_approval_request_metadata" }
      validate :validate_unique_pending_approval, on: [:create, :update]

      scope :pending_member_approvals, ->(member_namespace_id) do
        where(member_namespace_id: member_namespace_id).where(status: statuses[:pending])
      end

      scope :pending_member_approvals_with_max_new_access_level, -> do
        where(status: statuses[:pending]).select('DISTINCT ON (user_id) *')
                                         .order(:user_id, new_access_level: :desc, created_at: :asc)
      end

      scope :pending_member_approvals_for_user, ->(user_id) do
        where(status: statuses[:pending]).where(user_id: user_id)
                                         .order(id: :asc)
      end

      class << self
        def create_or_update_pending_approval(user, member_namespace, attributes)
          retries = 0

          begin
            approval = find_or_initialize_by(
              user: user,
              member_namespace: member_namespace,
              status: :pending
            ).tap do |record|
              record.assign_attributes(attributes)
              record.status = :pending
            end
            approval.save!

            approval
          rescue ActiveRecord::RecordNotUnique
            retries += 1
            retry if retries < 3
            raise
          end
        end
      end

      def hook_attrs
        {
          new_access_level: new_access_level,
          old_access_level: old_access_level,
          existing_member_id: member_id
        }
      end

      private

      def validate_unique_pending_approval
        return unless pending?

        scope = self.class.pending_member_approvals(member_namespace_id).where(user_id: user_id)
        scope = scope.where.not(id: id) if persisted?

        return unless scope.exists?

        errors.add(:base, 'A pending approval for the same user and namespace already exists.')
      end
    end
  end
end
