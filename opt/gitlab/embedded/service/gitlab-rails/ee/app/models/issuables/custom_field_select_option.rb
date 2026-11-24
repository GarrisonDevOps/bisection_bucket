# frozen_string_literal: true

module Issuables
  class CustomFieldSelectOption < ApplicationRecord
    belongs_to :namespace
    belongs_to :custom_field

    before_validation :copy_namespace_from_custom_field

    validates :namespace, :custom_field, presence: true
    validates :value, presence: true, length: { maximum: 255 }
    validate :unique_values

    scope :of_field, ->(field) { where(custom_field_id: field) }
    scope :with_case_insensitive_values, ->(values) { where('LOWER(value) IN (?)', values&.map(&:downcase)) }

    private

    def copy_namespace_from_custom_field
      self.namespace ||= custom_field&.namespace
    end

    def unique_values
      return if custom_field.blank? || value.blank?

      other_options = custom_field.select_options.reject { |o| o == self }
      return unless other_options.map(&:value).map(&:downcase).include?(value.downcase)

      errors.add(:value, :taken)
    end
  end
end
