# frozen_string_literal: true

module Security
  module InventoryFilters
    class AnalyzerStatusUpdateService
      include Security::InventoryFilters::ProjectAttributes

      def self.execute(projects, analyzer_statuses)
        new(projects, analyzer_statuses).execute
      end

      def initialize(projects, analyzer_statuses)
        @projects = projects
        @analyzer_statuses = analyzer_statuses
      end

      def execute
        return unless projects.present? && analyzer_statuses.present?

        upsert_inventory_filters_analyzer_statuses
      rescue StandardError => error
        Gitlab::ErrorTracking.track_exception(error, project_id: projects.first&.id)
      end

      private

      attr_reader :projects, :analyzer_statuses, :analyzer_type

      def upsert_inventory_filters_analyzer_statuses
        return if inventory_filters_data.empty?

        grouped_by_keys = inventory_filters_data.group_by do |record|
          analyzer_keys = record.keys.select { |k| k.in?(Enums::Security.extended_analyzer_types.keys) }
          analyzer_keys.sort
        end

        project_ids = inventory_filters_data.filter_map { |record| record[:project_id] }

        Security::InventoryFilter.transaction do
          # upsert in groups based on analyzers records keys. There should be a single update for single project,
          # and upto 2 updated for many projects because the bulk setting based update can only pass
          # setting type and the aggregated type as input to this service.
          grouped_by_keys.each_value do |records|
            Security::InventoryFilter.upsert_all(records, unique_by: :project_id)
          end

          Security::InventoryFilter.recompute_aggregate_booleans(project_ids)
        end
      end

      def project_id_to_attributes
        @project_id_to_attributes ||= build_project_attributes(projects)
      end

      def inventory_filters_data
        @inventory_filters_data ||= grouped_analyzer_statuses.filter_map do |project_id, statuses|
          build_inventory_filter_for_project(project_id, statuses)
        end
      end

      def grouped_analyzer_statuses
        @grouped_analyzer_statuses ||= analyzer_statuses.group_by { |status| status[:project_id] }
      end

      def build_inventory_filter_for_project(project_id, statuses)
        return unless project_id.present? && statuses.present?

        project_attributes = project_id_to_attributes[project_id]
        return unless project_attributes.present?

        analyzer_columns = statuses.each_with_object({}) do |status_hash, columns|
          analyzer_type = status_hash[:analyzer_type]
          next unless analyzer_type.in?(Enums::Security.extended_analyzer_types.keys)

          status = status_hash[:status]
          columns[analyzer_type] = Enums::Security.analyzer_statuses[status]
        end
        return if analyzer_columns.empty?

        { project_id: project_id }.merge(project_attributes).merge(analyzer_columns)
      end
    end
  end
end
