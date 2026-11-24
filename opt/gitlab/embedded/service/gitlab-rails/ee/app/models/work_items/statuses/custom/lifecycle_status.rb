# frozen_string_literal: true

module WorkItems
  module Statuses
    module Custom
      class LifecycleStatus < ApplicationRecord
        self.table_name = 'work_item_custom_lifecycle_statuses'

        belongs_to :namespace
        belongs_to :lifecycle, class_name: 'WorkItems::Statuses::Custom::Lifecycle'
        belongs_to :status, class_name: 'WorkItems::Statuses::Custom::Status'

        before_validation :copy_namespace_from_lifecycle

        validates :namespace, :lifecycle, :status, :position, presence: true
        validates :status_id, uniqueness: { scope: :lifecycle_id }
        validates :position, numericality: { greater_than_or_equal_to: 0, only_integer: true }

        private

        def copy_namespace_from_lifecycle
          self.namespace ||= lifecycle&.namespace
        end
      end
    end
  end
end
