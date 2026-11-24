# frozen_string_literal: true

module WorkItems
  class NumberFieldValue < ApplicationRecord
    include CustomFieldValue
    include ScalarCustomFieldValue

    validates :custom_field, uniqueness: { scope: [:work_item_id] }
    validates :value, presence: true, numericality: true
  end
end
