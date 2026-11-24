# frozen_string_literal: true

module Security
  module InventoryFilters
    class TriageCapabilitiesUpdateService
      include Security::InventoryFilters::ProjectAttributes

      def self.execute(project_to_capabilities)
        new(project_to_capabilities).execute
      end

      def initialize(project_to_capabilities)
        @project_to_capabilities = project_to_capabilities
      end

      def execute
        return if project_to_capabilities.blank?

        upsert_records
      rescue StandardError => error
        Gitlab::ErrorTracking.track_exception(error, project_count: project_to_capabilities.size)
        raise
      end

      private

      attr_reader :project_to_capabilities

      def upsert_records
        return if records.empty?

        Security::InventoryFilter.upsert_all(records, unique_by: :project_id)
      end

      def records
        @records ||= project_to_capabilities.filter_map do |project, capabilities|
          attrs = project_attributes[project.id]
          next unless attrs

          { project_id: project.id }.merge(attrs).merge(capabilities)
        end
      end

      def project_attributes
        @project_attributes ||= build_project_attributes(project_to_capabilities.keys)
      end
    end
  end
end
