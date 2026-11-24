# frozen_string_literal: true

module Security
  module Ascp
    class ComponentDependency < ::SecApplicationRecord
      self.table_name = 'ascp_component_dependencies'

      belongs_to :project
      belongs_to :component, class_name: 'Security::Ascp::Component', inverse_of: :dependencies
      belongs_to :dependency, class_name: 'Security::Ascp::Component', inverse_of: :dependents

      validates :project, :component, :dependency, presence: true
      validate :different_components

      scope :at_scan, ->(scan_id) { joins(:component).where(ascp_components: { scan_id: scan_id }) }

      private

      def different_components
        return unless component_id == dependency_id

        errors.add(:dependency, 'cannot be the same as component')
      end
    end
  end
end
