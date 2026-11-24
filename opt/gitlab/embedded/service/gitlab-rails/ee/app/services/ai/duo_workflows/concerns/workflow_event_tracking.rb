# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Concerns
      module WorkflowEventTracking
        extend ActiveSupport::Concern
        include ::Gitlab::InternalEventsTracking

        private

        def track_workflow_event(event_name, workflow, source: nil, additional_properties: {})
          track_internal_event(
            event_name,
            user: workflow.user,
            project: workflow.project,
            namespace: workflow.namespace,
            additional_properties: workflow_tracking_properties(event_name, workflow, source: source)
              .merge(additional_properties)
          )
        end

        def workflow_tracking_properties(event_name, workflow, source: nil)
          config = ci_agent_config(event_name, workflow)

          {
            label: workflow.workflow_definition,
            value: workflow.id,
            property: workflow.environment,
            source: source,
            verification_run: ('true' if workflow.triggered_by_verification?),
            image_source: (image_source_for(workflow, config) if config),
            custom_setup_script: (config.setup_script.present?.to_s if config),
            custom_network_policy: (network_policy_customized?(config).to_s if config),
            drop_reason: (workflow.drop_reason if event_name.to_s == 'agent_platform_session_dropped')
          }.compact
        end

        # Only a CI-executed session start reads .gitlab/duo/agent-config.yml. Elsewhere this is nil so
        # .compact drops the properties: absent means "could not apply", or that the read below failed.
        def ci_agent_config(event_name, workflow)
          return unless event_name == 'agent_platform_session_started'
          return unless workflow.project && workflow.from_pipeline?

          ::Gitlab::DuoAgentPlatform::Config.new(workflow.project)
        rescue StandardError => e
          # The transition is already committed, so an exception here would skip the rest of
          # UpdateWorkflowStatusService#handle_status_event.
          Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
          nil
        end

        # Config#network_policy fills in empty allowed_domains/denied_domains whenever the key is
        # present at all, so a bare `network_policy:` block is a non-empty Hash that restricts
        # nothing. Report on the values to keep no-op blocks out of the adoption numbers.
        def network_policy_customized?(config)
          config.network_policy&.values&.any?(&:present?) || false
        end

        # Mirrors the image resolution order in StartWorkflowService#workload_definition.
        def image_source_for(workflow, config)
          return 'session' if workflow.image.present?
          return 'agent_config' if config.default_image.present?
          return 'instance' if ::Gitlab::CurrentSettings.duo_workflows_default_image_registry.present?

          'default'
        end
      end
    end
  end
end
