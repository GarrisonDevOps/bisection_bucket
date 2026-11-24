# frozen_string_literal: true

module Vulnerabilities
  class TriggerSecretDetectionFalsePositiveDetectionWorkflowWorker
    include ApplicationWorker
    include Gitlab::InternalEventsTracking
    include Vulnerabilities::WorkflowTriggerable
    prepend Vulnerabilities::WorkflowTrackable

    StartWorkflowServiceError = Class.new(StandardError)
    WORKFLOW_DEFINITION = 'secrets_fp_detection/v1'
    WORKFLOW_NAME = 'secret detection false positive detection workflow'

    feature_category :vulnerability_management
    data_consistency :delayed
    defer_on_database_health_signal :gitlab_sec, [:vulnerabilities], 5.minutes
    urgency :throttled
    idempotent!
    concurrency_limit -> { 100 }
    sidekiq_options retry: 10

    sidekiq_retries_exhausted do |job, _exception|
      new.handle_retry_exhaustion(job)
    end

    def perform(vulnerability_id, execution_id = nil)
      vulnerability = find_vulnerability(vulnerability_id)
      return unless vulnerability

      return unless ::Feature.enabled?(:duo_secret_detection_false_positive, vulnerability.group)

      unless vulnerability.eligible_for_secret_detection_fp_detection?
        log_not_eligible(vulnerability)
        return
      end

      project = vulnerability.project

      user = resolve_workflow_user(vulnerability, project)
      unless user
        log_no_eligible_user(vulnerability, project)
        return
      end

      consumer = find_consumer(user, project)

      unless consumer
        log_consumer_not_found(vulnerability)
        return
      end

      service_account = find_service_account(consumer)

      unless service_account
        log_service_account_not_found(vulnerability, consumer, WORKFLOW_NAME)
        return
      end

      result = trigger_workflow(vulnerability, user, consumer, service_account, execution_id)

      if result.success?
        create_triggered_workflow_record(vulnerability, result)
        track_event(vulnerability)
      else
        handle_error(result, vulnerability)
      end
    rescue StandardError => error
      log_and_raise_exception(error, vulnerability_id)
    end

    protected

    def finding_from_args(vulnerability_id)
      find_vulnerability(vulnerability_id)&.finding
    end

    private

    def find_vulnerability(vulnerability_id)
      ::Vulnerability.find_by_id(vulnerability_id)
    end

    def trigger_workflow(vulnerability, user, consumer, service_account, execution_id)
      project = vulnerability.project

      flow_params = {
        item_consumer: consumer,
        service_account: service_account,
        execute_workflow: true,
        event_type: 'sidekiq_worker',
        user_prompt: vulnerability.id.to_s
      }
      # A bulk run is started by a person, so only automatic runs are system-triggered.
      flow_params[:trigger_source] = :system unless execution_id

      ::Ai::Catalog::Flows::ExecuteService.new(
        project: project,
        current_user: user,
        params: flow_params
      ).execute
    end

    def find_consumer(user, project)
      ::Ai::Catalog::ItemConsumersFinder.new(user, params: {
        project_id: project.id,
        item_type: Ai::Catalog::Item::FLOW_TYPE,
        foundational_flow_reference: WORKFLOW_DEFINITION,
        include_inherited: false
      }).execute.first
    end

    def find_service_account(consumer)
      if consumer.project.present?
        consumer.parent_item_consumer&.service_account
      else
        consumer.service_account
      end
    end

    def log_not_eligible(vulnerability)
      Gitlab::AppLogger.info(
        message: 'Vulnerability not eligible for secret detection false positive detection workflow',
        vulnerability_id: vulnerability.id,
        project_id: vulnerability.project_id,
        workflow_definition: WORKFLOW_DEFINITION
      )
    end

    def log_consumer_not_found(vulnerability)
      Gitlab::AppLogger.info(
        message: 'No consumer found for secret detection false positive detection workflow, ' \
          'setting is not enabled for this project',
        vulnerability_id: vulnerability.id,
        project_id: vulnerability.project_id,
        workflow_definition: WORKFLOW_DEFINITION
      )
    end

    def handle_error(result, vulnerability)
      Gitlab::AppLogger.error(
        message: 'Failed to call Secret Detection workflow service for vulnerability',
        vulnerability_id: vulnerability.id,
        project_id: vulnerability.project.id,
        error: result.message,
        reason: result.reason
      )

      raise StartWorkflowServiceError,
        "Failed to call Secret Detection workflow service for vulnerability #{result.message}"
    end

    def log_and_raise_exception(error, vulnerability_id)
      Gitlab::ErrorTracking.log_and_raise_exception(
        error,
        vulnerability_id: vulnerability_id
      )
    end

    def create_triggered_workflow_record(vulnerability, response)
      ::Vulnerabilities::TriggeredWorkflow.create!(
        vulnerability_occurrence_id: vulnerability.finding&.id,
        workflow: response.payload[:workflow],
        workflow_name: :secrets_fp_detection
      )
    rescue ActiveRecord::RecordInvalid => error
      Gitlab::ErrorTracking.track_exception(
        error,
        vulnerability_id: vulnerability.id,
        workflow_id: response.payload[:workflow_id]
      )

      nil
    end

    def track_event(vulnerability)
      track_internal_event(
        'trigger_secret_detection_vulnerability_fp_detection_workflow',
        project: vulnerability.project,
        additional_properties: {
          label: 'automatic',
          value: vulnerability.id,
          property: vulnerability.severity
        }
      )
    end
  end
end
