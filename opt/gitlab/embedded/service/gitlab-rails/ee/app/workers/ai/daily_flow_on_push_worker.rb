# frozen_string_literal: true

module Ai
  class DailyFlowOnPushWorker
    include ApplicationWorker

    data_consistency :sticky
    idempotent!
    deduplicate :until_executed, including_scheduled: true
    feature_category :duo_agent_platform
    urgency :low
    defer_on_database_health_signal :gitlab_main, [:projects], 1.minute
    concurrency_limit -> { 10 }

    def perform(project_id, pusher_id)
      project = Project.find_by_id(project_id)
      pusher = User.find_by_id(pusher_id)

      return unless project && pusher

      return unless Feature.enabled?(:sdlc_context_agent_trigger, project)
      return unless project.project_setting.duo_vulnerability_context_analysis_enabled

      return unless pusher.human?

      namespace_ids = project.namespace.self_and_ancestor_ids
      return unless ::Ai::Catalog::EnabledFoundationalFlow.for_namespace(namespace_ids).exists?

      lease_key = "sdlc_context_agent:#{project.id}"
      return unless ::Gitlab::ExclusiveLease.new(lease_key, timeout: 24.hours).try_obtain

      # The lease is intentionally not released on failure to prevent retry storms
      # within the 24-hour budget window.

      consumer = resolve_consumer(project)
      unless consumer
        logger.warn(structured_payload(message: 'No item consumer found for project, skipping.',
          project_id: project.id))
        return
      end

      trigger = build_synthetic_trigger(project, consumer)

      unless trigger.service_account
        logger.warn(structured_payload(message: 'Item consumer has no active service account, skipping.',
          project_id: project.id))
        return
      end

      ::Ai::FlowTriggers::RunService.new(
        project: project,
        current_user: pusher,
        flow_trigger: trigger,
        resource: nil
      ).execute(input: '', event: :commit_to_default_branch)
    end

    private

    def resolve_consumer(project)
      Ai::Catalog::ItemConsumer.find_by_project_and_flow_reference(
        project,
        'business_context_security_guidelines/experimental'
      )
    end

    def build_synthetic_trigger(project, consumer)
      Ai::FlowTrigger.new(
        project: project,
        ai_catalog_item_consumer: consumer,
        event_types: [Ai::FlowTrigger::EVENT_TYPES[:commit_to_default_branch]],
        description: 'Vulnerability context analysis agent daily push'
      )
    end
  end
end
