# frozen_string_literal: true

module Ai
  class NamespaceFoundationalAgentStatus < ApplicationRecord
    self.table_name = 'namespace_foundational_agent_statuses'

    belongs_to :namespace, class_name: 'Namespace'

    scope :enabled, -> { where(enabled: true) }

    validates :reference, presence: true, length: { maximum: 255 }
    validates :enabled, inclusion: { in: [true, false] }
    validates :reference, uniqueness: { scope: :namespace_id }

    validate :validate_reference_exists

    private

    def validate_reference_exists
      return if FoundationalChatAgent.any_agents_with_reference?(reference)

      errors.add(:reference, "is not a valid foundational agent reference")
    end
  end
end
