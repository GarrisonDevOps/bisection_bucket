# frozen_string_literal: true

module Groups
  class SavedReply < ApplicationRecord
    def self.namespace_foreign_key
      :group_id
    end
    self.table_name = :group_saved_replies

    include SavedReplyConcern

    belongs_to :group

    scope :for_groups, ->(group_ids) { where(group_id: group_ids) }
  end
end
