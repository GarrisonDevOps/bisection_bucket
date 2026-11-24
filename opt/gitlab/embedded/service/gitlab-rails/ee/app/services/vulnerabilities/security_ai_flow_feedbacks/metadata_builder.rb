# frozen_string_literal: true

module Vulnerabilities
  module SecurityAiFlowFeedbacks
    # Snapshots finding and flow metadata for security AI flow feedback events. Only the listed keys are emitted,
    # and free-form values are restricted to GitLab-defined vocabularies: anything from a self-hosted model,
    # a third-party scanner, or an unrecognized CWE, OWASP, or extension pattern is replaced or dropped.
    class MetadataBuilder
      include Gitlab::Utils::StrongMemoize

      FLOW_TYPES_BY_ORIGIN = {
        ::Vulnerabilities::Flag::AI_SAST_FP_DETECTION_ORIGIN => 'sast_fp_detection',
        ::Vulnerabilities::Flag::AI_SECRET_DETECTION_FP_DETECTION_ORIGIN => 'secrets_fp_detection'
      }.freeze

      METADATA_KEYS = %i[
        cwe owasp severity report_type scanner_external_id scanner_vendor
        rule_identifier_type file_extension has_data_flow
        ai_confidence_score ai_verdict flow_version model_name model_provider
      ].freeze

      EXTRA_KEYS = %i[dismissal_reason from_state to_state].freeze

      MAX_VALUE_LENGTH = 255
      # Capped like the Snowplow AI context, so the values still fit if the event becomes a Duo event.
      AI_CONTEXT_KEYS = %i[flow_version model_name model_provider].freeze
      AI_CONTEXT_MAX_LENGTH = 64
      CODE_FLOWS_DETAIL_TYPE = 'code-flows'
      GITLAB_MODEL_PROVIDER = ::Ai::ModelSelection::FeaturesConfigurable::MODEL_PROVIDER
      GITLAB_SCANNER_VENDOR = 'GitLab'
      # From the GitLab SAST and secret detection analyzers' reports.
      GITLAB_SCANNER_EXTERNAL_IDS = %w[
        semgrep gitlab-advanced-sast gitlab-advanced-sast-cpp kics pmd-apex sobelow find_sec_bugs kubesec
        gitleaks gitlab-secret-scanner
      ].freeze
      GITLAB_RULE_IDENTIFIER_TYPES = %w[
        semgrep_id gitlab-advanced-sast_id gitlab-advanced-sast-cpp_id kics_id pmd_apex_rule_id sobelow_rule_id
        find_sec_bugs_type kubesec_rule_id gitleaks_rule_id gitlab_secret_scanner_rule_id cwe
      ].freeze
      SELF_HOSTED_MODEL = 'self_hosted'
      CUSTOM_SCANNER = 'custom'
      OTHER_FILE_EXTENSION = 'other'
      FILE_EXTENSION_PATTERN = /\A[a-z0-9]{1,10}\z/
      CWE_PATTERN = /\ACWE-\d+\z/
      OWASP_PATTERN = /\AA\d{1,2}:\d{4}\z/

      def initialize(flag, extras: {})
        @flag = flag
        @finding = flag.finding
        @extras = extras.to_h.symbolize_keys.slice(*EXTRA_KEYS)
      end

      def flow_type
        FLOW_TYPES_BY_ORIGIN[flag.origin]
      end

      def workflow
        flag.workflow || latest_triggered_workflow
      end
      strong_memoize_attr :workflow

      def build
        metadata = {
          cwe: cwe,
          owasp: owasp,
          severity: finding.severity,
          report_type: finding.report_type,
          **scanner_attributes,
          file_extension: file_extension,
          has_data_flow: data_flow?,
          ai_confidence_score: flag.confidence_score,
          ai_verdict: flag.status,
          flow_version: flow_metadata['flow_version'],
          **model_attributes
        }.merge(extras)

        metadata.slice(*METADATA_KEYS, *EXTRA_KEYS).to_h do |key, value|
          [key, truncate(value, AI_CONTEXT_KEYS.include?(key) ? AI_CONTEXT_MAX_LENGTH : MAX_VALUE_LENGTH)]
        end
      end

      private

      attr_reader :flag, :finding, :extras

      def latest_triggered_workflow
        # A row created after the flag was written belongs to a later run of the flow.
        finding.triggered_workflows
          .with_workflow_name(flow_type)
          .created_at_or_before(flag.updated_at)
          .order_by_created_at_desc
          .first&.workflow
      end

      def cwe
        value = finding.cwe_value

        value if value.is_a?(String) && CWE_PATTERN.match?(value)
      end

      def owasp
        finding.identifiers
          .select { |identifier| identifier.external_type.casecmp?('owasp') }
          .map(&:external_id)
          .select { |external_id| external_id.is_a?(String) && OWASP_PATTERN.match?(external_id) }
          .sort
          .join(',')
          .presence
      end

      def file_extension
        extension = File.extname(finding.file.to_s).delete_prefix('.').downcase.presence
        return unless extension

        FILE_EXTENSION_PATTERN.match?(extension) ? extension : OTHER_FILE_EXTENSION
      end

      # Third-party and custom scanners can put customer-defined names in these fields, and any report can claim the
      # GitLab vendor, so only known GitLab values are sent. Rule IDs are never sent, because custom rulesets on GitLab
      # analyzers still report the GitLab vendor.
      def scanner_attributes
        scanner = finding.scanner
        primary_identifier = finding.primary_identifier

        unless scanner.vendor == GITLAB_SCANNER_VENDOR
          return {
            scanner_external_id: CUSTOM_SCANNER,
            scanner_vendor: CUSTOM_SCANNER,
            rule_identifier_type: CUSTOM_SCANNER
          }
        end

        {
          scanner_external_id: allowlisted(scanner.external_id, GITLAB_SCANNER_EXTERNAL_IDS),
          scanner_vendor: scanner.vendor,
          rule_identifier_type: allowlisted(primary_identifier.external_type, GITLAB_RULE_IDENTIFIER_TYPES)
        }
      end

      def allowlisted(value, allowed)
        allowed.include?(value) ? value : CUSTOM_SCANNER
      end

      # Self-hosted model metadata carries the admin-defined model name, endpoint, and API key,
      # so only GitLab-managed model metadata is read.
      def model_attributes
        return { model_name: nil, model_provider: nil } if model_metadata.empty?

        unless model_metadata['provider'] == GITLAB_MODEL_PROVIDER
          return { model_name: SELF_HOSTED_MODEL, model_provider: SELF_HOSTED_MODEL }
        end

        {
          model_name: model_metadata['identifier'].presence || model_metadata['name'],
          model_provider: GITLAB_MODEL_PROVIDER
        }
      end

      def data_flow?
        finding.details.values.any? do |detail|
          detail.is_a?(Hash) && detail['type'] == CODE_FLOWS_DETAIL_TYPE
        end
      end

      def flow_metadata
        parse_json(workflow&.flow_metadata_json)
      end
      strong_memoize_attr :flow_metadata

      def model_metadata
        parse_json(workflow&.model_metadata_json)
      end
      strong_memoize_attr :model_metadata

      def parse_json(json)
        return {} if json.blank?

        parsed = ::Gitlab::Json.safe_parse(json)
        parsed.is_a?(Hash) ? parsed : {}
      rescue JSON::ParserError
        {}
      end

      def truncate(value, length)
        value.is_a?(String) ? value.truncate(length) : value
      end
    end
  end
end
