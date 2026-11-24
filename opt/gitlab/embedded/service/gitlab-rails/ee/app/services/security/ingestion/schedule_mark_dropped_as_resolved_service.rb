# frozen_string_literal: true

module Security
  module Ingestion
    # Service for finding unresolved vulnerabilities whose identifiers
    # are no longer being reported.
    #
    # This service works by taking the list of primary_identifiers from `report.scan`,
    # finds any outstanding vulnerabilities not linked to those identifiers,
    # and marks them as resolved
    class ScheduleMarkDroppedAsResolvedService
      BATCH_SIZE = 100
      DELAY_INTERVAL = 20.seconds.to_i

      def self.execute(project_id, scan_type, primary_identifiers)
        new(project_id, scan_type, primary_identifiers).execute
      end

      def initialize(project_id, scan_type, primary_identifiers)
        @project_id = project_id
        @scan_type = scan_type
        @primary_identifiers = primary_identifiers
      end

      def execute
        dropped_identifiers.each_slice(BATCH_SIZE).with_index(1) do |identifiers, index|
          delay = DELAY_INTERVAL * index
          ::Vulnerabilities::MarkDroppedAsResolvedWorker.perform_in(
            delay,
            project_id,
            identifiers.map(&:id)
          )
        end
      rescue StandardError => error
        # failure should not block the rest of the ingestion process
        Gitlab::ErrorTracking.track_exception(
          error, project_id: @project_id, scan_type: @scan_type, primary_identifiers: @primary_identifiers)
      end

      private

      attr_reader :project_id, :scan_type, :primary_identifiers

      # Returns a list of identifiers no longer present in latest scan
      # limited to identifier types present in the primary_identifiers
      def dropped_identifiers
        return [] unless primary_identifiers&.any?

        dropped_identifiers = []

        vulnerabilities_resolved_on_default_branch.each_batch(of: BATCH_SIZE) do |batch|
          dropped_identifiers.concat(
            identifiers_no_longer_matching(batch)
          )
        end

        dropped_identifiers.uniq.sort
      end

      # Returns a list of identifiers not included in scan's primary_identifiers
      def identifiers_no_longer_matching(vulnerabilities)
        existing_identifiers_for(vulnerabilities).reject do |existing_identifier|
          type_unresovable?(existing_identifier) ||
            present_in_scan?(existing_identifier)
        end
      end

      # Returns true if the existing identifier's type is not returned by
      # the scan and thus cannot be considered auto-resolvable
      def type_unresovable?(existing_identifier)
        primary_identifier_types.exclude?(existing_identifier.external_type)
      end

      def present_in_scan?(existing_identifier)
        scanned_identifier_keys.include?(
          [existing_identifier.external_type, existing_identifier.external_id]
        )
      end

      def existing_identifiers_for(vulnerabilities)
        unresolved_findings = ::Vulnerabilities::Finding.by_vulnerability(
          vulnerabilities.select(:vulnerability_id)
        )

        ::Vulnerabilities::Identifier.id_in(
          unresolved_findings.select(:primary_identifier_id)
        )
      end

      def vulnerabilities_resolved_on_default_branch
        ::Vulnerabilities::Read
          .with_report_types(scan_type)
          .with_states(:detected)
          .resolved_on_default_branch
          .by_projects(::Project.non_archived.id_in(project_id).pluck_primary_key)
          .order_detected_at_desc
      end

      def primary_identifier_types
        @primary_identifier_types ||= primary_identifiers.map(&:external_type).to_set
      end

      def scanned_identifier_keys
        @scanned_identifier_keys ||= primary_identifiers.map do |identifier|
          [identifier.external_type, identifier.external_id]
        end.to_set
      end
    end
  end
end
