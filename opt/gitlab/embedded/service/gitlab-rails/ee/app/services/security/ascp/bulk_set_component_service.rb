# frozen_string_literal: true

module Security
  module Ascp
    class BulkSetComponentService
      include Gitlab::Utils::StrongMemoize

      BATCH_SIZE = 100
      MAX_COMPONENTS = 500
      UNMATCHED_SAMPLE_SIZE = 100
      ROOT_SUB_DIRECTORY = "."

      def initialize(project:, finding_ids:)
        @project = project
        @finding_ids = Array(finding_ids)
      end

      def execute
        return success(matched: 0, unmatched: 0, removed: 0) if finding_ids.empty?
        return too_many_components_error if components.size > MAX_COMPONENTS
        return success(matched: 0, unmatched: 0, removed: 0) if components.empty?

        unmatched_with_file_ids = []

        totals = finding_ids.each_slice(BATCH_SIZE).each_with_object(matched: 0, unmatched: 0, removed: 0) do |ids, acc|
          rows = []
          unmatched_ids = []

          findings_by_ids(ids).each do |finding|
            component_id = matching_component_id(finding.file)

            if component_id
              rows << build_row(finding, component_id)
            else
              unmatched_ids << finding.id
              unmatched_with_file_ids << finding.id if finding.file.present?
            end
          end

          acc[:matched] += upsert_links(rows)
          acc[:unmatched] += unmatched_ids.size
          acc[:removed] += delete_links(unmatched_ids)
        end

        log_unmatched_with_files(unmatched_with_file_ids)

        success(**totals)
      end

      private

      attr_reader :project, :finding_ids

      # [[id, sub_directory], ...] ordered most-specific first, so the first
      # match for a file path is the longest matching prefix.
      def components
        return [] unless latest_scan

        Security::Ascp::Component
          .at_scan(latest_scan.id)
          .pluck_id_and_sub_directory(MAX_COMPONENTS + 1)
          .sort_by { |_id, sub_directory| [root?(sub_directory) ? 1 : 0, -sub_directory.length] }
      end
      strong_memoize_attr :components

      def latest_scan
        Security::Ascp::Scan.by_project(project.id).latest.first
      end
      strong_memoize_attr :latest_scan

      def findings_by_ids(ids)
        Vulnerabilities::Finding.id_in(ids).by_projects([project.id])
      end

      def matching_component_id(file_path)
        return if file_path.blank?

        components.find { |_id, sub_directory| within_sub_directory?(file_path, sub_directory) }&.first
      end

      def within_sub_directory?(file_path, sub_directory)
        return true if root?(sub_directory)

        file_path == sub_directory || file_path.start_with?("#{sub_directory}/")
      end

      def root?(sub_directory)
        sub_directory == ROOT_SUB_DIRECTORY
      end

      def build_row(finding, component_id)
        {
          vulnerability_occurrence_id: finding.id,
          ascp_component_id: component_id,
          project_id: finding.project_id,
          created_at: now,
          updated_at: now
        }
      end

      def upsert_links(rows)
        return 0 if rows.empty?

        table = Vulnerabilities::AscpComponentLink.arel_table
        on_duplicate = Arel.sql(
          "#{table[:ascp_component_id].name} = EXCLUDED.#{table[:ascp_component_id].name}, " \
            "#{table[:updated_at].name} = EXCLUDED.#{table[:updated_at].name} " \
            "WHERE #{table.name}.#{table[:ascp_component_id].name} " \
            "IS DISTINCT FROM EXCLUDED.#{table[:ascp_component_id].name}"
        )

        Vulnerabilities::AscpComponentLink.upsert_all(
          rows,
          unique_by: :vulnerability_occurrence_id,
          on_duplicate: on_duplicate
        )

        rows.size
      end

      def delete_links(ids)
        return 0 if ids.empty?

        Vulnerabilities::AscpComponentLink.by_finding_ids(ids).delete_all
      end

      def log_unmatched_with_files(unmatched_ids)
        return if unmatched_ids.empty?

        Gitlab::AppJsonLogger.error(
          message: "Findings with a file path did not match an ASCP component",
          project_id: project.id,
          unmatched_count: unmatched_ids.size,
          unmatched_finding_ids: unmatched_ids.first(UNMATCHED_SAMPLE_SIZE)
        )
      end

      # Matching against a truncated component set would delete links that a
      # dropped component still owns, so skip the run entirely instead.
      def too_many_components_error
        Gitlab::AppJsonLogger.error(
          message: "Skipped ASCP component matching because the scan has too many components",
          project_id: project.id,
          scan_id: latest_scan.id,
          max_components: MAX_COMPONENTS
        )

        ServiceResponse.error(
          message: "Latest ASCP scan has more than #{MAX_COMPONENTS} components",
          reason: :too_many_components,
          payload: { matched: 0, unmatched: 0, removed: 0 }
        )
      end

      def success(matched:, unmatched:, removed:)
        ServiceResponse.success(payload: { matched: matched, unmatched: unmatched, removed: removed })
      end

      def now
        Time.current
      end
      strong_memoize_attr :now
    end
  end
end
