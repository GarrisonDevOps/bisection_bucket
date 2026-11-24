# frozen_string_literal: true

module WorkItems
  class DateFieldValue < ApplicationRecord
    include CustomFieldValue
    include ScalarCustomFieldValue

    validates :custom_field, uniqueness: { scope: [:work_item_id] }
    validates :value, presence: true
  end
end
