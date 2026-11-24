# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class DiffService
      def initialize(project, new_analyzer_statuses)
        @project = project
        @new_analyzer_statuses = new_analyzer_statuses
        @diff = {}
      end

      def execute
        process_new_statuses

        diff_with_metadata
      end

      attr_reader :project, :new_analyzer_statuses, :diff

      private

      def extract_processed_types
        new_analyzer_statuses.keys
      end

      def fetch_current_statuses
        @current_statuses ||= project.analyzer_statuses.index_by(&:analyzer_type)
          .transform_keys(&:to_sym)
      end

      def process_new_statuses
        return unless new_analyzer_statuses.present?

        current_statuses = fetch_current_statuses
        new_analyzer_statuses.each do |analyzer_type, status_data|
          new_status = status_data[:status].to_s
          current_record = current_statuses[analyzer_type]
          old_status = current_record&.status.to_s

          update_diff_if_status_changed(analyzer_type, old_status, new_status)
        end
      end

      def update_diff_if_status_changed(analyzer_type, old_status, new_status)
        return if new_status == old_status

        record_status_change(analyzer_type, old_status, new_status)
      end

      def record_status_change(analyzer_type, old_status, new_status)
        diff[analyzer_type] ||= {}
        diff[analyzer_type][new_status] ||= 0
        diff[analyzer_type][new_status] += 1

        return if old_status.empty?

        diff[analyzer_type][old_status] ||= 0
        diff[analyzer_type][old_status] -= 1
      end

      def diff_with_metadata
        return {} unless diff.present?

        {
          namespace_id: project.namespace.id,
          traversal_ids: project.namespace.traversal_ids,
          diff: diff
        }
      end
    end
  end
end
