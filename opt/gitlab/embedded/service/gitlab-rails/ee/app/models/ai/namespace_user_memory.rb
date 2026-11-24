# frozen_string_literal: true

module Ai
  class NamespaceUserMemory < ApplicationRecord
    self.table_name = 'namespace_ai_user_memories'

    include Ai::UserMemoryable

    belongs_to :namespace, optional: false, inverse_of: :ai_user_memories

    validates :user_id, uniqueness: { scope: :namespace_id }
    validate :namespace_is_top_level_group

    private

    def namespace_is_top_level_group
      return if namespace.nil?
      return if namespace.root? && namespace.group_namespace?

      errors.add(:namespace, _('must be a top-level group'))
    end
  end
end
