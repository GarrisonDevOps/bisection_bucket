# frozen_string_literal: true

module Vulnerabilities
  class TriggerResolutionWorkflowWorker
    include ApplicationWorker
    include Gitlab::InternalEventsTracking
    include Gitlab::Utils::StrongMemoize
    include Vulnerabilities::WorkflowTriggerable
    prepend Vulnerabilities::WorkflowTrackable

    sidekiq_retries_exhausted do |job, _exception|
      new.handle_retry_exhaustion(job)
    end

    StartWorkflowServiceError = Class.new(StandardError)

    data_consistency :delayed
    feature_category :vulnerability_management
    urgency :throttled
    idempotent!
    concurrency_limit -> { 100 }
    sidekiq_options retry: 10
    skip_composite_identity_passthrough!

    CONFIDENCE_THRESHOLD = 0.6
    WORKFLOW_DEFINITION = 'resolve_sast_vulnerability/v1'
    WORKFLOW_NAME = 'vulnerability resolution workflow'

    # Rejections that a retry cannot change.
    CHAIN_REJECTION_REASONS = %i[
      invalid_trigger_source
      parent_workflow_namespace_mismatch
      trigger_depth_exceeded
      chain_root_not_human
      trigger_breadth_exceeded
    ].freeze

    # `parent_workflow_id` is the workflow that wrote the flag, only passed when chaining is enabled.
    def perform(item_id, execution_id = nil, parent_workflow_id = nil)
      if chained?(item_id, parent_workflow_id)
        # Running without the parent would reset the chain and lift its limits.
        caller_context = chain_caller_context(item_id, parent_workflow_id)
        return unless caller_context
      end

      finding = execution_id ? find_bulk_finding(item_id) : find_automatic_finding(item_id, caller_context)
      return unless finding
      return if execution_id && !finding.sast?
      return unless finding.resolution_workflow_enabled?

      vulnerability = finding.vulnerability
      project = finding.project

      user = workflow_user(finding, caller_context)
      return unless user

      consumer = find_consumer(user, project)
      unless consumer
        log_consumer_not_found(finding)
        return
      end

      service_account = find_service_account(consumer)

      unless service_account
        log_service_account_not_found(vulnerability, consumer, WORKFLOW_NAME)
        return
      end

      result = trigger_workflow(vulnerability, user, consumer, service_account,
        caller_context: caller_context, bulk: execution_id.present?)
      handle_result(result, finding, caller_context)
    rescue StandardError => error
      log_exception(error, item_id, execution_id, finding&.vulnerability_id)
    end

    protected

    def finding_from_args(finding_uuid)
      find_bulk_finding(finding_uuid)
    end

    private

    def find_automatic_finding(vulnerability_flag_id, caller_context)
      vulnerability_flag = find_vulnerability_flag(vulnerability_flag_id)
      return unless vulnerability_flag

      if caller_context && caller_context.root_human.nil?
        return log_chain_skip(:chain_root_not_human, caller_context.parent_workflow.id,
          vulnerability_flag_id: vulnerability_flag_id)
      end

      return unless vulnerability_flag.eligible_for_resolution_workflow?(caller_context)

      vulnerability_flag.finding
    end

    # Disabling the flag after enqueue restores the unchained run, as CreateWorkflowService would
    # drop the parent anyway.
    def chained?(vulnerability_flag_id, parent_workflow_id)
      return false unless parent_workflow_id

      vulnerability_flag = find_vulnerability_flag(vulnerability_flag_id)
      return false unless vulnerability_flag

      Feature.enabled?(:ai_flow_trigger_chaining, vulnerability_flag.finding.project.root_ancestor)
    end

    def chain_caller_context(vulnerability_flag_id, parent_workflow_id)
      parent_workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(parent_workflow_id)
      return ::Ai::FlowTriggers::CallerContext.new(parent_workflow: parent_workflow) if parent_workflow

      log_chain_skip(:parent_workflow_not_found, parent_workflow_id, vulnerability_flag_id: vulnerability_flag_id)
    end

    def workflow_user(finding, caller_context)
      return chain_root_user(caller_context, finding) if caller_context

      user = resolve_workflow_user(finding.vulnerability, finding.project)
      log_no_eligible_user(finding.vulnerability, finding.project) unless user
      user
    end

    # Eligibility has already checked that this user exists and may use Duo workflows in the project.
    def chain_root_user(caller_context, finding)
      user = caller_context.root_human
      parent_workflow = caller_context.parent_workflow
      return user if Ability.allowed?(user, :update_duo_workflow, parent_workflow)

      log_chain_skip(:parent_workflow_not_authorized, parent_workflow.id, **finding_log_context(finding))
    end

    def log_chain_skip(reason, parent_workflow_id, **context)
      Gitlab::AppLogger.info(
        message: 'Skipped vulnerability resolution workflow started by another workflow',
        skip_reason: reason,
        parent_workflow_id: parent_workflow_id,
        **context
      )

      nil
    end

    def finding_log_context(finding)
      {
        vulnerability_id: finding.vulnerability_id,
        finding_id: finding.id,
        Labkit::Fields::GL_PROJECT_ID => finding.project_id
      }
    end

    def find_bulk_finding(finding_uuid)
      strong_memoize_with(:find_bulk_finding, finding_uuid) do
        ::Vulnerabilities::Finding.by_uuid(finding_uuid).first
      end
    end

    def find_vulnerability_flag(vulnerability_flag_id)
      strong_memoize_with(:find_vulnerability_flag, vulnerability_flag_id) do
        ::Vulnerabilities::Flag.with_associations.find_by_id(vulnerability_flag_id)
      end
    end

    def handle_result(result, finding, caller_context)
      if result.success?
        track_event(finding) if create_triggered_workflow_record(finding, result)
      elsif caller_context && CHAIN_REJECTION_REASONS.include?(result.reason)
        log_chain_skip(result.reason, caller_context.parent_workflow.id, **finding_log_context(finding))
      else
        handle_error(result, finding)
      end
    end

    def trigger_workflow(vulnerability, user, consumer, service_account, caller_context:, bulk:)
      flow_params = {
        item_consumer: consumer,
        service_account: service_account,
        execute_workflow: true,
        event_type: 'sidekiq_worker',
        user_prompt: vulnerability.id.to_s
      }

      # A chained run gets the flow trigger source from its parent, and a bulk run is started by a person.
      if caller_context
        flow_params[:parent_workflow] = caller_context.parent_workflow
      elsif !bulk
        flow_params[:trigger_source] = :system
      end

      ::Ai::Catalog::Flows::ExecuteService.new(
        project: vulnerability.project,
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

    def log_consumer_not_found(finding)
      Gitlab::AppLogger.error(
        message: 'No consumer configured for vulnerability resolution workflow',
        finding_id: finding.id,
        project_id: finding.project_id,
        workflow_definition: WORKFLOW_DEFINITION
      )
    end

    def create_triggered_workflow_record(finding, response)
      workflow = response.payload[:workflow]
      return unless workflow

      ::Vulnerabilities::TriggeredWorkflow.create!(
        vulnerability_occurrence_id: finding.id,
        workflow_id: workflow.id,
        workflow_name: :resolve_sast_vulnerability
      )
    rescue ActiveRecord::RecordInvalid => error
      Gitlab::ErrorTracking.track_exception(
        error,
        vulnerability_id: finding.vulnerability_id,
        workflow_id: workflow&.id
      )

      nil
    end

    def handle_error(result, finding)
      Gitlab::AppLogger.error(
        message: 'Failed to create and start workflow for vulnerability resolution',
        vulnerability_id: finding.vulnerability_id,
        finding_id: finding.id,
        error: result.message,
        reason: result.reason
      )

      raise StartWorkflowServiceError, "Failed to start workflow for vulnerability resolution: #{result.message}"
    end

    def log_exception(error, item_id, execution_id, vulnerability_id)
      context = { vulnerability_id: vulnerability_id }

      if execution_id
        context[:execution_id] = execution_id
        context[:finding_uuid] = item_id
      else
        context[:vulnerability_flag_id] = item_id
      end

      Gitlab::ErrorTracking.log_and_raise_exception(error, **context)
    end

    def track_event(finding)
      vulnerability = finding.vulnerability

      track_internal_event(
        'trigger_sast_vulnerability_resolution_workflow',
        project: finding.project,
        additional_properties: {
          label: 'automatic',
          value: vulnerability.id,
          property: vulnerability.severity
        }
      )
    end
  end
end
