# frozen_string_literal: true

module Security
  class ApprovalPolicyMergeRequestBypassEvent < ApplicationRecord
    self.table_name = 'approval_policy_merge_request_bypass_events'

    belongs_to :project
    belongs_to :security_policy, class_name: 'Security::Policy'
    belongs_to :merge_request
    belongs_to :user, optional: true

    validates :reason, presence: true, length: { maximum: 1024 }
    validates_uniqueness_of :project_id, scope: [:merge_request_id, :security_policy_id]
  end
end
