# frozen_string_literal: true

module Vulnerabilities
  class AutoDismissWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :delayed
    feature_category :security_policy_management
    urgency :low
    deduplicate :until_executed
    idempotent!
    defer_on_database_health_signal :gitlab_sec, [:vulnerabilities, :vulnerability_reads], 5.minutes

    def handle_event(event)
      findings = event.data['findings']
      return if findings.blank?

      pipeline_finding_map = group_by_pipeline_id(findings)
      pipeline_ids = pipeline_finding_map.keys.compact
      return if pipeline_ids.blank?

      pipelines = Ci::Pipeline.id_in(pipeline_ids).index_by(&:id)
      pipeline_finding_map.each do |pipeline_id, findings|
        pipeline = pipelines[pipeline_id]
        next unless pipeline

        handle_pipeline_findings(pipeline, findings)
      end
    end

    private

    def handle_pipeline_findings(pipeline, findings)
      project = pipeline.project
      return unless ::Security::PolicyAvailability.any_available?(project)

      vulnerability_ids = extract_vulnerability_ids(findings)
      result = Vulnerabilities::AutoDismissService.new(pipeline, vulnerability_ids).execute

      if result.error?
        Gitlab::AppJsonLogger.error(
          message: "Failed to auto-dismiss vulnerabilities from event",
          project_id: project.id,
          pipeline_id: pipeline.id,
          error: result.message,
          reason: result.reason
        )
      elsif result.payload[:count] > 0
        Gitlab::AppJsonLogger.debug(
          message: "Auto-dismissed vulnerabilities from event",
          project_id: project.id,
          pipeline_id: pipeline.id,
          count: result.payload[:count]
        )
      end
    end

    def group_by_pipeline_id(findings)
      findings.group_by { |finding| finding['pipeline_id'] }
    end

    def extract_vulnerability_ids(findings)
      findings.filter_map { |finding| finding['vulnerability_id'] }.uniq
    end
  end
end
