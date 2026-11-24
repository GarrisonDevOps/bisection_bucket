# frozen_string_literal: true

module Security
  module Ingestion
    # This entity is used in ingestion services to
    # map security_finding - report_finding - vulnerability_id - finding_id
    #
    # You can think this as the Message object in the pipeline design pattern
    # which is passed between tasks.
    class FindingMap
      FINDING_ATTRIBUTES = %i[metadata_version name raw_metadata report_type severity details description message solution].freeze

      attr_reader :pipeline, :tracked_context, :security_finding, :report_finding
      attr_accessor :finding_id, :vulnerability_id, :new_record, :transitioned_to_detected, :identifier_ids

      delegate :uuid, :scanner_id, :severity, to: :security_finding
      delegate :scan, to: :security_finding, private: true
      delegate :project, to: :pipeline
      delegate :evidence, :context_unaware_uuid, to: :report_finding

      def initialize(pipeline, tracked_context, security_finding, report_finding)
        @pipeline = pipeline
        @tracked_context = tracked_context
        @security_finding = security_finding
        @report_finding = report_finding
        @identifier_ids = []
      end

      def identifiers
        @identifiers ||= report_finding.identifiers.first(Vulnerabilities::Finding::MAX_NUMBER_OF_IDENTIFIERS)
      end

      def identifier_data
        identifiers.map do |identifier|
          identifier.to_hash.merge(project_id: project.id)
        end
      end

      def set_identifier_ids_by(fingerprint_id_map)
        @identifier_ids = identifiers.map { |identifier| fingerprint_id_map[identifier.fingerprint] }
      end

      def to_hash
        report_finding.to_hash
                      .slice(*FINDING_ATTRIBUTES)
                      .merge!(
                        uuid: uuid,
                        new_uuid: context_unaware_uuid,
                        security_project_tracked_context_id: tracked_context&.id,
                        scanner_id: scanner_id,
                        primary_identifier_id: identifier_ids.first,
                        location: report_finding.location_data,
                        location_fingerprint: report_finding.location_fingerprint,
                        project_id: project.id,
                        initial_pipeline_id: pipeline.id,
                        latest_pipeline_id: pipeline.id
                      )
      end

      def new_or_transitioned_to_detected?
        new_record || transitioned_to_detected
      end
    end
  end
end
