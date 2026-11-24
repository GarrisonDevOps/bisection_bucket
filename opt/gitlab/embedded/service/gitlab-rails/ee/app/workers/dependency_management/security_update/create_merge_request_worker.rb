# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class CreateMergeRequestWorker
      include Gitlab::EventStore::Subscriber

      feature_category :dependency_management
      data_consistency :sticky
      urgency :low
      idempotent!
      deduplicate :until_executing, including_scheduled: true
      defer_on_database_health_signal :gitlab_sec, [:vulnerabilities], 1.minute

      WORKLOAD_JOB_NAME = 'workload'

      def handle_event(event)
        pipeline = Ci::Pipeline.find_by_id_and_partition(event.data[:pipeline_id], event.data[:partition_id])
        return unless pipeline
        return unless pipeline.dependency_management_security_update? # source enum guard
        return unless pipeline.success?

        project = pipeline.project
        return unless project.licensed_feature_available?(:dependency_scanning)

        vulnerability = find_vulnerability(pipeline, project)
        return unless vulnerability

        result = ::DependencyManagement::SecurityUpdate::CreateMergeRequestService.new(
          project: project,
          pipeline: pipeline,
          vulnerability: vulnerability
        ).execute

        log_service_result(result, pipeline, vulnerability)
      end

      private

      def find_vulnerability(pipeline, project)
        workload_job = pipeline.find_job_with_archive_artifacts(WORKLOAD_JOB_NAME)

        unless workload_job
          Gitlab::AppLogger.error(
            message: 'DependencyManagement::SecurityUpdate::CreateMergeRequestWorker: job producing artifact not found',
            pipeline_id: pipeline.id,
            project_id: project.id
          )

          return
        end

        vulnerability_id = workload_job.variables[UpdateService::VULNERABILITY_ID_VARIABLE]&.value.to_i

        return unless vulnerability_id.nonzero?

        project.vulnerabilities.find_by_id(vulnerability_id).tap do |vuln|
          next if vuln

          Gitlab::AppLogger.warn(
            message: 'DependencyManagement::SecurityUpdate::CreateMergeRequestWorker: vulnerability not found',
            pipeline_id: pipeline.id,
            vulnerability_id: vulnerability_id,
            project_id: project.id
          )
        end
      end

      def log_service_result(result, pipeline, vulnerability)
        unless result.success?
          Gitlab::AppLogger.error(
            message: 'DependencyManagement::SecurityUpdate: failed to create merge request',
            pipeline_id: pipeline.id,
            vulnerability_id: vulnerability.id,
            reason: result.message
          )
          return
        end

        return if result.payload[:skipped]

        Gitlab::AppLogger.info(
          message: 'DependencyManagement::SecurityUpdate: merge request created or updated',
          pipeline_id: pipeline.id,
          vulnerability_id: vulnerability.id,
          merge_request_id: result.payload[:merge_request].id
        )
      end
    end
  end
end
