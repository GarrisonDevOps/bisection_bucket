# frozen_string_literal: true

module MergeRequests
  class AiSuggestedReviewer < ApplicationRecord
    include BulkInsertSafe
    include PartitionedTable

    RETENTION_PERIOD = 30.days

    self.table_name = 'p_ai_suggested_reviewers'
    self.primary_key = :id

    partitioned_by :created_at, strategy: :daily, retain_for: RETENTION_PERIOD

    REASON_LIMIT = 2048

    belongs_to :merge_request
    belongs_to :user
    belongs_to :project
    belongs_to :approval_merge_request_rule, optional: true
    belongs_to :approval_project_rule, optional: true

    before_validation :set_project, prepend: true

    validates :reason, length: { maximum: REASON_LIMIT }, allow_nil: true
    validate :only_one_approval_rule_association

    scope :excluding_reviewers, ->(user_ids) { where.not(user_id: user_ids) }
    scope :for_users, ->(user_ids) { where(user_id: user_ids) }
    scope :preload_user_and_approval_rules, -> { preload(:user, :approval_merge_request_rule, :approval_project_rule) }
    scope :order_id_asc, -> { order(id: :asc) }
    scope :for_merge_request, ->(merge_request) { where(merge_request_id: merge_request) }

    def approval_rule
      approval_merge_request_rule || approval_project_rule
    end

    private

    def set_project
      self.project_id ||= merge_request&.target_project_id
    end

    def only_one_approval_rule_association
      return if approval_merge_request_rule_id.blank? || approval_project_rule_id.blank?

      errors.add(:base, _('Cannot be associated with both an approval merge request rule and an approval project rule'))
    end
  end
end
