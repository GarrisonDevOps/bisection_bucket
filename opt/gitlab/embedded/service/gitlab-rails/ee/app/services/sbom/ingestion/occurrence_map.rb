# frozen_string_literal: true

module Sbom
  module Ingestion
    # Data structure for tracking SBOM component state during ingestion.
    #
    # OccurrenceMap is the SBOM equivalent of {Security::Ingestion::FindingMap},
    # serving as the "message object" in the pipeline design pattern. It bridges
    # report data (from the CycloneDX parser) with database records, accumulating
    # IDs and state as it flows through ingestion tasks.
    #
    # == Pipeline Design Pattern
    #
    # During SBOM ingestion, an OccurrenceMap is created for each component in the
    # report. As it passes through tasks:
    #
    # 1. Starts with `report_component` and `report_source` from the parsed report
    # 2. Tasks populate `component_id`, `component_version_id`, `source_id` as
    #    records are created or found
    # 3. `occurrence_id` is set when the occurrence record is created
    # 4. `vulnerability_ids` accumulates if vulnerabilities are linked
    #
    # == Key Attributes
    #
    # Read-only (from report):
    # - `report_component` - The parsed component from CycloneDX (name, version, purl)
    # - `report_source` - The source context (dependency file, container image)
    #
    # Mutable (set by tasks):
    # - `component_id` - FK to sbom_components table
    # - `component_version_id` - FK to sbom_component_versions table
    # - `source_id` - FK to sbom_sources table
    # - `source_package_id` - FK to sbom_source_packages table
    # - `occurrence_id` - FK to sbom_occurrences table (created record)
    # - `uuid` - Unique identifier for the occurrence
    # - `vulnerability_ids` - Array of linked vulnerability IDs
    # - `occurrence_changed` - Flag indicating if occurrence was updated
    # - `policy_dismissal_changed` - Flag indicating a preserved policy dismissal newly covers the occurrence
    #
    # == Derived Data
    #
    # - `#to_h` - Returns attributes hash suitable for bulk insertion
    # - `#purl_type` - Package URL type from the component's purl
    # - `#packager` - Package manager (npm, gem, pip, etc.)
    # - `#input_file_path` - Path to the manifest file or container image ref
    #
    # @see Security::Ingestion::FindingMap for the security equivalent
    # @see OccurrenceMapCollection for the collection wrapper
    # @see IngestReportService for the orchestration layer
    class OccurrenceMap
      include Gitlab::Utils::StrongMemoize

      attr_reader :report_component, :report_source
      attr_accessor :component_id, :component_version_id, :source_id, :occurrence_id, :source_package_id, :uuid,
        :vulnerability_ids, :vulnerability_finding_ids_map, :occurrence_changed, :ref_created,
        :policy_dismissal_changed, :security_project_tracked_context

      def initialize(report_component, report_source, security_project_tracked_context = nil)
        @report_component = report_component
        @report_source = report_source
        @security_project_tracked_context = security_project_tracked_context
        @vulnerability_ids = []
        @vulnerability_finding_ids_map = {}
        @occurrence_changed = false
        @ref_created = false
        @policy_dismissal_changed = false
      end

      def to_h
        {
          component_id: component_id,
          component_version_id: component_version_id,
          component_type: report_component.component_type,
          name: report_component.name,
          purl_type: purl_type,
          source_id: source_id, source_type: report_source&.source_type,
          source: report_source&.data,
          source_package_id: source_package_id,
          source_package_name: report_component.source_package_name,
          sbom_occurrence_id: occurrence_id,
          security_project_tracked_context_id: security_project_tracked_context_id,
          uuid: uuid,
          version: version
        }
      end

      def version_present?
        version.present?
      end

      def purl_type
        report_component.purl&.type
      end

      def packager
        report_component&.properties&.packager || report_source&.packager
      end

      def input_file_path
        return image_ref if container_scanning_component? && image_data_present?

        report_source&.input_file_path
      end

      def security_project_tracked_context_id
        security_project_tracked_context&.id
      end

      delegate :image_name, :image_tag, to: :report_source, allow_nil: true
      delegate :name, :version, :source_package_name, :ancestors, :reachability, to: :report_component

      private

      def image_data_present?
        image_name.present? && image_tag.present?
      end

      def container_scanning_component?
        report_component.properties&.source_type&.to_sym == :trivy
      end

      def image_ref
        "container-image:#{image_name}:#{image_tag}"
      end
    end
  end
end
