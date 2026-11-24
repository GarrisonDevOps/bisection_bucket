# frozen_string_literal: true

module Projects
  class SavedReply < ApplicationRecord
    def self.namespace_foreign_key
      :project_id
    end
    self.table_name = :project_saved_replies

    include SavedReplyConcern

    belongs_to :project
  end
end
