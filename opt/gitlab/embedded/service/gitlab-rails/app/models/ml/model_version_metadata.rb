# frozen_string_literal: true

module Ml
  class ModelVersionMetadata < ApplicationRecord
    include Ml::BulkInsertableMetadata

    validates :name, length: { maximum: 255 }, presence: true
    validates :name, uniqueness: { scope: :model_version, message: TAKEN_MESSAGE }, unless: :taken_names
    validate :name_not_taken, if: :taken_names
    validates :value, length: { maximum: 5000 }, presence: true

    belongs_to :project, optional: false
    belongs_to :model_version, class_name: 'Ml::ModelVersion', optional: false
  end
end
