# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class AnalyzePipelineExecutionPolicyConfigService < BaseProjectService
      def execute
        content = YAML.dump(params[:content])
        default_branch = project.default_branch_or_main
        default_sha = project.repository.root_ref_sha
        config = Gitlab::Ci::Config.new(content,
          project: project,
          user: current_user,
          ref: default_branch,
          sha: default_sha
        )

        unless config.valid?
          return ServiceResponse.error(
            message: "Error occurred while parsing the CI configuration: #{config.errors}",
            payload: build_payload
          )
        end

        config_hash = config.to_hash
        analyzers_config = extract_analyzers_from_config(config_hash)

        scans = analyzers_config.keys & Security::MergeRequestSecurityReportGenerationService::ALLOWED_REPORT_TYPES
        ServiceResponse.success(payload: build_payload(scans: scans))
      rescue StandardError => e
        ServiceResponse.error(message: e.message, payload: build_payload)
      end

      private

      def build_payload(scans: [])
        { enforced_scans: scans }
      end

      def extract_analyzers_from_config(config)
        artifact_reports = config.select { |_key, entry| entry.is_a?(Hash) && entry.dig(:artifacts, :reports).present? }
              .map { |_key, entry| entry.dig(:artifacts, :reports) }

        artifact_reports.each_with_object({}) do |reports, obj|
          reports.each do |report_type, path|
            obj[report_type] ||= Set.new
            obj[report_type] << path
          end
        end.with_indifferent_access
      end
    end
  end
end
