# frozen_string_literal: true

module Notes
  class NoteDuoMetadata < ApplicationRecord
    self.table_name = :note_duo_metadata
    self.primary_key = :note_id

    belongs_to :namespace
    belongs_to :note, inverse_of: :duo_metadata
    belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow'

    validates :note, presence: true
    validates :namespace, presence: true
    validates :workflow_id, presence: true, uniqueness: { scope: :note_id }
  end
end
