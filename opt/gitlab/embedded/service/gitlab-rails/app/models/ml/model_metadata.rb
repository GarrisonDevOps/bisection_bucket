# frozen_string_literal: true

module Ml
  class ModelMetadata < ApplicationRecord
    include Ml::BulkInsertableMetadata

    validates :name, length: { maximum: 255 }, presence: true
    validates :name, uniqueness: { scope: :model, message: TAKEN_MESSAGE }, unless: :taken_names
    validate :name_not_taken, if: :taken_names
    validates :value, length: { maximum: 5000 }, presence: true

    belongs_to :model, class_name: 'Ml::Model', optional: false
  end
end
