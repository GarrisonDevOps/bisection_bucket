# frozen_string_literal: true

module WorkItems
  class DecisionOption < ApplicationRecord
    self.table_name = 'work_item_decision_options'

    # Soft limits, deliberately below the DB check constraints (1024/2048) so
    # they can be raised without a migration
    CONTENT_LENGTH_MAX = 500
    DESCRIPTION_LENGTH_MAX = 800

    belongs_to :decision,
      class_name: 'WorkItems::Decision',
      foreign_key: :work_item_decision_id,
      inverse_of: :options
    belongs_to :namespace

    validates :decision, presence: true
    validates :namespace, presence: true
    validates :content, presence: true, length: { maximum: CONTENT_LENGTH_MAX }
    validates :description, length: { maximum: DESCRIPTION_LENGTH_MAX }
    validate :options_count_within_limit, on: :create

    before_validation :set_namespace

    private

    def options_count_within_limit
      return unless decision

      # Counts persisted siblings only (this record is unsaved), so reaching
      # the max means this record would be option max + 1
      limit = WorkItems::Decision.options_limit(selected: selected?)
      return if decision.options.count < limit

      errors.add(:base, format(_('Decision cannot have more than %{max} options'), max: limit))
    end

    def set_namespace
      return if decision.nil?
      return if decision.namespace_id == namespace_id

      self.namespace_id = decision.namespace_id
    end
  end
end
