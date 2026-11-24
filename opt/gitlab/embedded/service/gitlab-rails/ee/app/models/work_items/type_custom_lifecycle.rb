# frozen_string_literal: true

module WorkItems
  class TypeCustomLifecycle < ApplicationRecord
    include WorkItems::TypesFramework::HasType

    self.table_name = 'work_item_type_custom_lifecycles'

    belongs_to :namespace
    belongs_to :lifecycle, class_name: 'WorkItems::Statuses::Custom::Lifecycle'

    before_validation :copy_namespace_from_lifecycle

    validates :namespace, :lifecycle, presence: true
    validates :work_item_type_id, presence: true, uniqueness: { scope: :namespace_id }
    validate :validate_status_widget_availability

    scope :with_namespace_id, ->(namespace_id) { where(namespace_id: namespace_id) }

    private

    def copy_namespace_from_lifecycle
      self.namespace ||= lifecycle&.namespace
    end

    def validate_status_widget_availability
      return if work_item_type.nil?
      return if namespace.nil?
      return if work_item_type.widgets(namespace).map(&:widget_type).include?('status')

      errors.add(:work_item_type, 'does not support status widget')
    end
  end
end
