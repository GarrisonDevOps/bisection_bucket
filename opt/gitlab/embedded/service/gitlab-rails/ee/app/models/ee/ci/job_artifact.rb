# frozen_string_literal: true

module EE
  # CI::JobArtifact EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `Ci::JobArtifact` model
  module Ci::JobArtifact
    include ::Gitlab::Utils::StrongMemoize
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel
      include ::Geo::ReplicableCiArtifactable

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :job_artifact_state)

      with_replicator ::Geo::JobArtifactReplicator

      has_one :job_artifact_state,
        ->(artifact) { in_partition(artifact) },
        autosave: false,
        inverse_of: :job_artifact,
        partition_foreign_key: :partition_id,
        class_name: '::Geo::JobArtifactState'

      EE_REPORT_FILE_TYPES = EE::Enums::Ci::JobArtifact.ee_report_file_types

      scope :security_reports, ->(file_types: ::Enums::Ci::JobArtifact.security_report_and_cyclonedx_report_file_types) do
        requested_file_types = *file_types
        valid_file_types = requested_file_types & ::Enums::Ci::JobArtifact.security_report_and_cyclonedx_report_file_types

        with_file_types(valid_file_types)
      end

      scope :security_reports_by_build_and_type_pairs, ->(build_type_pairs) do
        return security_reports.none if build_type_pairs.empty?

        table = arel_table
        conditions = build_type_pairs.map do |build_id, file_type|
          table[:job_id].eq(build_id).and(table[:file_type].eq(file_type))
        end.reduce(:or)

        security_reports.where(conditions)
      end

      skip_callback :commit, :after, :geo_create_event!, if: :store_after_commit?

      # Job artifacts create their verification state in file_stored_*_hooks, once the file is stored.
      # The generic callback would run before a direct-upload trace is uploaded (#634502).
      skip_callback :save, :after, :save_verification_details
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of projects associated, based on the query given in `query`.
      #
      # @param [String] query term that will search over projects :path, :name and :description
      #
      # @return [ActiveRecord::Relation<Ci::JobArtifact>] a collection of job artifacts
      def search(query)
        return all if query.empty?

        # This is divided into two separate queries, one for the CI and one for the main database
        for_project(::Project.search(query).limit(1000).pluck_primary_key)
      end

      override :associated_file_types_for
      def associated_file_types_for(file_type)
        return file_types_for_report(:license_scanning) if file_types_for_report(:license_scanning).include?(file_type)
        return file_types_for_report(:browser_performance) if file_types_for_report(:browser_performance).include?(file_type)

        super
      end

      override :verification_state_table_class
      def verification_state_table_class
        ::Geo::JobArtifactState
      end

      override :file_types_for_report
      def file_types_for_report(report_type)
        EE_REPORT_FILE_TYPES.fetch(report_type) { super }
      end

      override :create_verification_details_for
      def create_verification_details_for(primary_keys)
        job_artifacts = find(primary_keys)

        rows = job_artifacts.map do |artifact|
          { verification_state_model_key => artifact.id, :partition_id => artifact.partition_id }
        end

        verification_state_table_class.insert_all(rows, unique_by: %i[job_artifact_id partition_id])
      end
    end

    override :file_stored_after_transaction_hooks
    def file_stored_after_transaction_hooks
      super

      is_being_created = previous_changes.key?(:id) && previous_changes[:id].first.nil?

      geo_create_event! if is_being_created

      save_verification_details
    end

    override :file_stored_in_transaction_hooks
    def file_stored_in_transaction_hooks
      super

      save_verification_details
    end

    def job_artifact_state
      super || build_job_artifact_state
    end

    def verification_state_object
      job_artifact_state
    end

    # Returns all Security::Report objects produced from this artifact.
    # For most artifact types this is a single-element array. For SARIF artifacts
    # a single file can contain multiple tool runs, each yielding its own report.
    # StoreScanService iterates this array to create one Security::Scan per report.
    def security_reports(validate: false)
      strong_memoize(:security_reports) do
        next [] unless file_type.in?(::Enums::Ci::JobArtifact.security_report_and_cyclonedx_report_file_types)

        signatures_enabled = project.licensed_feature_available?(:vulnerability_finding_signatures)

        reports = build_security_reports(signatures_enabled: signatures_enabled, validate: validate)
        next [] unless reports.present?

        # Deduplicate findings within each individual report
        reports.map { |report| ::Security::MergeReportsService.new(report).execute }
      end
    end

    # Compatibility shim: callers that only need a single report (e.g. ScanArtifactComparator,
    # Security::Scan#security_report) use the first entry from the full set.
    def security_report(validate: false)
      security_reports(validate: validate).first
    end

    def build_security_reports(signatures_enabled:, validate:)
      if file_type == 'cyclonedx'
        sbom_reports = parse_sbom_reports
        report = ::Gitlab::VulnerabilityScanning::SecurityReportBuilder.new(
          sbom_reports: sbom_reports, project: project, pipeline: job.pipeline).execute
        return Array(report)
      end

      parse_security_reports(signatures_enabled: signatures_enabled, validate: validate)
    end

    def parse_sbom_reports
      ::Gitlab::Ci::Reports::Sbom::Reports.new.tap do |sbom_reports|
        each_blob do |blob|
          ::Gitlab::Ci::Reports::Sbom::Report.new.tap do |report|
            ::Gitlab::Ci::Parsers.fabricate!(file_type).parse!(blob, report)
            sbom_reports.add_report(report)
          end
        end
      end
    end

    def parse_security_reports(signatures_enabled:, validate:)
      report = base_security_report

      unless size.to_i > 0
        report.add_error('EmptyFile', 'Report file is empty')
        return [report]
      end

      run_reports = []
      each_blob do |blob|
        result = ::Gitlab::Ci::Parsers.fabricate!(
          file_type, blob, report, signatures_enabled: signatures_enabled, validate: validate
        ).parse!

        # Most parsers (Common subclasses) mutate `report` in place and return the raw
        # parsed-data hash; the return value is intentionally discarded for those.
        # Multi-report parsers (e.g. SARIF with multiple runs) return an Array of
        # Security::Report objects representing one scan per tool run.
        if result.is_a?(Array) && result.all?(::Gitlab::Ci::Reports::Security::Report)
          run_reports.concat(result)
        end
      rescue StandardError
        report.add_error('ParsingError', 'Failed to parse security report')
      end

      # When multi-run parsers (e.g. SARIF) produce per-run reports, those are
      # the primary output. Parse errors are captured on `report` (which has no
      # findings in this path), so propagate them onto each run report so every
      # resulting Security::Scan carries the error context.
      #
      # `report` is itself in run_reports on a validation failure, so appending
      # its errors back onto it would grow the array being iterated forever. Two
      # guards, either sufficient alone: dup snapshots the list, and excluding
      # the base avoids the re-append. Kept both since the failure mode is an
      # instance-crashing hang.
      if run_reports.any?
        if report.errored?
          base_errors = report.errors.dup
          base_errors.each do |error|
            run_reports.excluding(report).each do |r|
              r.add_error(error[:type], error[:message])
            end
          end
        end

        run_reports
      else
        [report]
      end
    end

    def base_security_report
      ::Gitlab::Ci::Reports::Security::Report.new(file_type, job.pipeline, nil)
    end

    # This method is necessary to remove the reference to the
    # security report objects which allows GC to free the memory
    # slots in vm_heap occupied for the report objects and their
    # dependents.
    def clear_security_report
      clear_memoization(:security_reports)
    end
  end
end
