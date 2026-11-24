# frozen_string_literal: true

module ApprovalRuleUserLike
  extend ActiveSupport::Concern
  include EachBatch

  included do
    scope :for_users, ->(user_ids) { where(user_id: user_ids) }
  end
end
