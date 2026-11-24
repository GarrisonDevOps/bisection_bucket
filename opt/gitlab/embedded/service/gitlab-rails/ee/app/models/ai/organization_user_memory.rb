# frozen_string_literal: true

module Ai
  class OrganizationUserMemory < ApplicationRecord
    self.table_name = 'organization_ai_user_memories'

    include Ai::UserMemoryable

    belongs_to :organization,
      optional: false,
      class_name: 'Organizations::Organization',
      inverse_of: :ai_user_memories

    validates :user_id, uniqueness: { scope: :organization_id }
  end
end
