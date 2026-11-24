# frozen_string_literal: true

module ComplianceManagement
  class ProjectComplianceEvaluatorWorker
    include ApplicationWorker

    version 1
    data_consistency :sticky
    feature_category :compliance_management
    deduplicate :until_executed, including_scheduled: true
    idempotent!
    # :throttled, not :low: concurrency_limit buffering counts toward :low's 60s
    # queueing SLO by design; :throttled has no queueing target.
    urgency :throttled
    # Each job runs hundreds of queries against the primary; uncapped, a scheduler fan-out
    # can exhaust the shared Sidekiq DB connection pool.
    CONCURRENCY_LIMIT = 30
    concurrency_limit -> { CONCURRENCY_LIMIT }

    def self.schedule_compliance_evaluation(framework_id, project_ids)
      perform_in(
        ComplianceManagement::ComplianceFramework::ProjectSettings::PROJECT_EVALUATOR_WORKER_DELAY,
        framework_id, project_ids
      )
    end

    def perform(framework_id, project_ids)
      framework = ::ComplianceManagement::Framework.find_by_id(framework_id)
      return unless framework

      # Intersection with framework.project_ids makes sure that the framework is still associated with the projects
      # to be processed
      project_ids &= framework.project_ids
      projects = ::Project.id_in(project_ids).to_a
      return if projects.empty?

      requirements = framework.requirements_with_controls.to_a
      runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new

      projects.each_with_index do |project, index|
        approval_settings = framework.approval_settings_from_security_policies(project)

        requirements.each do |requirement|
          requirement.compliance_requirements_controls.each do |control|
            if control.external?
              # Only trigger external control service for ping-enabled controls
              if control.ping_enabled?
                ::ComplianceManagement::ComplianceFramework::ComplianceRequirements::TriggerExternalControlService
                  .new(project, control).execute
              end
            else
              status = ::ComplianceManagement::ComplianceRequirements::ExpressionEvaluator.new(control,
                project, approval_settings).evaluate

              update_control_status(project, control, status_value(status))
            end
          rescue StandardError => e
            Gitlab::ErrorTracking.log_exception(
              e,
              framework_id: control.compliance_requirement.framework_id,
              control_id: control.id,
              project_id: project.id
            )
          end

          update_requirement_status(project, requirement)
        end

        # The limiter is checked at the project boundary to keep each project's evaluation atomic.
        next unless runtime_limiter.over_time?

        remaining_project_ids = project_ids - projects.first(index + 1).map(&:id)
        if remaining_project_ids.any?
          self.class.schedule_compliance_evaluation(framework_id, remaining_project_ids)
          log_extra_metadata_on_done(:rescheduled_project_count, remaining_project_ids.size)
        end

        break
      end
    end

    private

    def status_value(status)
      case status
      when :not_applicable
        'not_applicable'
      when true
        'pass'
      else
        'fail'
      end
    end

    def update_control_status(project, control, status)
      ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::UpdateStatusService.new(
        current_user: ::Gitlab::Audit::UnauthenticatedAuthor.new,
        control: control,
        project: project,
        status_value: status
      ).execute
    rescue StandardError => e
      Gitlab::ErrorTracking.log_exception(
        e,
        framework_id: control.compliance_requirement.framework_id,
        control_id: control.id,
        project_id: project.id,
        status_value: status
      )
    end

    def update_requirement_status(project, requirement)
      requirement_status = ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus
        .find_or_create_project_and_requirement(project, requirement)

      ComplianceManagement::ComplianceFramework::ComplianceRequirements::RefreshStatusService.new(requirement_status)
        .execute
    end
  end
end
