# frozen_string_literal: true

module Ai
  class OrganizationFoundationalAgentStatus < ApplicationRecord
    self.table_name = 'organization_foundational_agent_statuses'

    belongs_to :organization,
      class_name: 'Organizations::Organization',
      inverse_of: :foundational_agents_status_records

    validates :reference, presence: true, uniqueness: { scope: :organization_id }, length: { maximum: 255 }
    validates :enabled, inclusion: { in: [true, false] }

    validate :validate_reference_exists

    private

    def validate_reference_exists
      return if reference.blank?
      return if FoundationalChatAgent.any_agents_with_reference?(reference)

      errors.add(:reference, "is not a valid foundational agent reference")
    end
  end
end
