# frozen_string_literal: true

module WorkItems
  class TypeCustomField < ApplicationRecord
    include WorkItems::TypesFramework::HasType

    self.table_name = 'work_item_type_custom_fields'

    belongs_to :namespace
    belongs_to :custom_field, class_name: 'Issuables::CustomField'

    before_validation :copy_namespace_from_custom_field

    validates :namespace, :work_item_type, presence: true
    validates :custom_field, presence: true, uniqueness: { scope: [:namespace_id, :work_item_type_id] }

    private

    def copy_namespace_from_custom_field
      self.namespace ||= custom_field&.namespace
    end
  end
end
