# frozen_string_literal: true

module Security
  module SecretDetection
    class UpdateTokenStatusService
      include Gitlab::InternalEventsTracking

      DEFAULT_BATCH_SIZE = 100

      attr_reader :project

      def initialize(token_lookup_service = TokenLookupService.new)
        @token_lookup_service = token_lookup_service
      end

      # For Vulnerabilities::Finding (default branch pipelines)
      def execute_for_vulnerability_pipeline(pipeline_id)
        return unless setup_and_validate_pipeline(pipeline_id)

        relation = ::Vulnerabilities::Finding
          .report_type('secret_detection')
          .by_latest_pipeline(pipeline_id)

        track_count = 0
        relation.each_batch(of: DEFAULT_BATCH_SIZE) do |batch|
          process_findings_batch(batch, :vulnerability)
          track_count += batch.size

          Vulnerabilities::PartnerTokenService.process_finding_async(batch, project)
        end

        track_internal_event(
          'number_of_tokens_processed_by_token_status_service',
          project: @project,
          additional_properties: {
            label: 'vulnerability', # Type of pipeline that triggered token status processing: security or vulnerability
            value: track_count # Number of secret detection findings sent to UpdateTokenStatusService for processing
          }
        )
      end

      # For ::Security::Finding (MR pipelines)
      def execute_for_security_pipeline(pipeline_id)
        return unless setup_and_validate_pipeline(pipeline_id)

        relation = @pipeline.security_findings.by_report_types(['secret_detection'])

        track_count = 0
        relation.each_batch(of: DEFAULT_BATCH_SIZE) do |batch|
          process_findings_batch(batch, :security)
          Security::PartnerTokenService.process_finding_async(batch, project)
          track_count += batch.size
        end

        track_internal_event(
          'number_of_tokens_processed_by_token_status_service',
          project: @project,
          additional_properties: {
            label: 'security', # Type of pipeline that triggered token status processing: security or vulnerability
            value: track_count # Number of secret detection findings sent to UpdateTokenStatusService for processing
          }
        )
      end

      # Single Vulnerabilities::Finding
      def execute_for_vulnerability_finding(finding_id)
        vulnerability_finding = ::Vulnerabilities::Finding.find_by_id(finding_id)
        return unless vulnerability_finding

        @project = vulnerability_finding.project
        return unless can_run?(@project)

        @pipeline = vulnerability_finding.latest_finding_pipeline

        Vulnerabilities::PartnerTokenService.process_partner_finding(vulnerability_finding)
        process_findings_batch([vulnerability_finding], :vulnerability)
      end

      # Single Security::Finding
      def execute_for_security_finding(security_finding_id)
        security_finding = ::Security::Finding.find_by_id(security_finding_id)
        return unless security_finding

        Security::PartnerTokenService.process_partner_finding(security_finding)
        execute_for_gitlab_security_finding(security_finding)
      end

      def execute_for_gitlab_security_finding(security_finding)
        @project = security_finding.project
        return unless can_run?(@project)

        @pipeline = security_finding.pipeline

        # partitions tied to current pipeline's scans
        partition = [security_finding.partition_number].compact

        # Update all findings with matching UUID (same secret, same location across commits)
        # to maintain consistent token status across pipelines
        all_security_findings = ::Security::Finding.by_project_id_and_uuid(@project.id, partition,
          security_finding.uuid)

        process_findings_batch(all_security_findings, :security)

        # Also update associated vulnerability finding, if there is one.
        return unless security_finding.vulnerability_finding

        process_findings_batch([security_finding.vulnerability_finding], :vulnerability)
      end

      private

      def can_run?(project)
        project.security_setting&.validity_checks_enabled
      end

      # The registry-membership gate lives here, not at the call sites: the
      # union in ValiditySupport would otherwise report a partner-only token
      # type as :supported for this service's verification path.
      def eligible_for_scanner_target?(token_type, finding)
        return false unless TokenLookupService.supported_token_type?(token_type)

        ValiditySupport.state(
          token_type: token_type,
          source: Scanners.target_for_finding(finding)
        ) == :supported
      end

      def setup_and_validate_pipeline(pipeline_id)
        @pipeline = Ci::Pipeline.find_by_id(pipeline_id)
        @project = @pipeline&.project
        @pipeline && can_run?(@project)
      end

      def process_findings_batch(findings, finding_type)
        return if findings.empty?

        tokens_by_raw = get_tokens_by_raw_token_value(findings, finding_type)
        attrs_by_raw = build_token_status_attributes_by_raw_token(findings, finding_type)

        merge_token_status_into_attributes(tokens_by_raw, attrs_by_raw)

        attributes_to_upsert = attrs_by_raw.values.flatten
        return if attributes_to_upsert.empty?

        case finding_type
        when :vulnerability
          model_class = ::Vulnerabilities::FindingTokenStatus
          unique_by = :vulnerability_occurrence_id
          error_message = "Failed to upsert vulnerability finding token statuses"
        when :security
          model_class = ::Security::FindingTokenStatus
          unique_by = :security_finding_id
          error_message = "Failed to upsert security finding token statuses"
        else
          raise ArgumentError, "Unknown finding type: #{finding_type}"
        end

        begin
          model_class.upsert_all(
            attributes_to_upsert,
            unique_by: unique_by,
            update_only: [:status, :updated_at, :last_verified_at],
            record_timestamps: false
          )

          sync_elasticsearch_for(findings, finding_type)

          status_by_finding_id = attributes_to_upsert.each_with_object({}) do |attr, hash|
            hash[attr[unique_by]] = attr[:status]
          end

          track_token_verifications(findings, status_by_finding_id)
        rescue StandardError => e
          handle_upsert_error(e, attributes_to_upsert, error_message)
        end
      end

      def sync_elasticsearch_for(findings, finding_type)
        return unless finding_type == :vulnerability

        vulnerability_ids = Array(findings).map(&:vulnerability_id)
        ::Vulnerabilities::EsHelper.sync_elasticsearch(vulnerability_ids)
      end

      def merge_token_status_into_attributes(tokens_by_raw, attrs_by_raw)
        tokens_by_raw.each do |raw_token, token|
          now = Time.current
          attrs_by_raw[raw_token]&.each do |finding_token_status_attr|
            finding_token_status_attr[:status] = ::Security::TokenStatus.for(token)
            finding_token_status_attr[:updated_at] = now
            finding_token_status_attr[:last_verified_at] = now
          end
        end
      end

      def track_token_verifications(findings, status_by_finding_id)
        findings.each do |finding|
          status = status_by_finding_id[finding.id]
          next unless status

          track_internal_event(
            'secret_detection_token_verified',
            project: @project,
            namespace: @project&.namespace,
            additional_properties: {
              label: finding.token_type,
              property: status.to_s
            }
          )
        end
      end

      def handle_upsert_error(exception, attributes_to_upsert, error_message)
        Gitlab::ErrorTracking.track_exception(
          exception,
          pipeline_id: @pipeline&.id,
          project_id: @project&.id,
          finding_count: attributes_to_upsert.size
        )

        Gitlab::AppLogger.error(
          message: error_message,
          exception: exception.class.name,
          exception_message: exception.message,
          pipeline_id: @pipeline&.id,
          project_id: @project&.id,
          finding_count: attributes_to_upsert.size
        )

        # Re-raise the exception to trigger Sidekiq retry mechanism
        raise
      end

      # Retrieves token objects by their raw token values from findings
      #
      # @param findings [ActiveRecord::Relation] Secret detection findings containing token information
      # @param finding_type Type of finding, either :vulnerability or :security
      # @return [Hash] A hash mapping raw token values to their corresponding token objects
      #
      # This method:
      # 1. Groups findings by token type (PAT, Deploy Token, etc.)
      # 2. Performs separate lookups for each token type using the appropriate lookup method
      # 3. Returns a combined hash of all found tokens indexed by their raw values
      def get_tokens_by_raw_token_value(findings, finding_type)
        # organise detected tokens by type
        raw_token_values_by_token_type = findings.each_with_object({}) do |finding, result|
          case finding_type
          when :vulnerability
            token_type = finding.token_type
            raw_token = finding.metadata['raw_source_code_extract']
          when :security
            token_type = finding.token_type
            raw_token = finding.finding_data['raw_source_code_extract']
          end

          next unless raw_token.present? && token_type
          next unless eligible_for_scanner_target?(token_type, finding)

          result[token_type] ||= []
          result[token_type] << raw_token

          result
        end

        # Find tokens and index by raw token
        raw_token_values_by_token_type.each_with_object({}) do |(token_type, raw_token_values), result_hash|
          type_tokens = @token_lookup_service.find(token_type, raw_token_values)
          result_hash.merge!(type_tokens) if type_tokens
        rescue StandardError => e
          Gitlab::AppLogger.warn(
            message: "Failed to lookup tokens for type #{token_type}",
            exception: e.class.name,
            exception_message: e.message
          )
          next
        end
      end

      # Unified attribute building for both finding types
      def build_token_status_attributes_by_raw_token(findings, finding_type)
        now = Time.current
        findings.each_with_object({}) do |finding, attr_by_raw_token|
          case finding_type
          when :vulnerability
            token_value = finding.metadata['raw_source_code_extract']
            token_type = finding.token_type
            id_key = :vulnerability_occurrence_id
          when :security
            token_value = finding.finding_data['raw_source_code_extract']
            token_type = finding.token_type
            id_key = :security_finding_id
          end

          next unless token_value.present? && token_type
          next unless eligible_for_scanner_target?(token_type, finding)

          attr_by_raw_token[token_value] ||= []
          attributes = {
            project_id: finding.project_id,
            status: 'unknown',
            created_at: now,
            updated_at: now,
            last_verified_at: now
          }
          attributes[id_key] = finding.id
          attr_by_raw_token[token_value] << attributes
        end
      end
    end
  end
end
