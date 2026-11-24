# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    # Starts the Duo flow for scheduled agentic scans as the policy trigger's autonomous account.
    class RunScheduledAgenticScanService < ::BaseProjectService
      include ::Gitlab::Loggable

      # Must be the flow enabled for the project, or the consumer lookup matches nothing and every scan skips.
      SCAN_TYPE_TO_FLOW_REFERENCE = {
        "business_logic" => ::Ai::Catalog::FoundationalFlow::BL_SECURITY_FLOW_REFERENCE
      }.freeze

      def execute
        agentic_actions = Array(params[:actions]).uniq { |action| action[:scan].to_s }
        return ServiceResponse.success(payload: { triggered: [] }) if agentic_actions.empty?

        unless ::Security::ScanExecutionPolicy.agentic_scan_available?(project)
          log_skip('Agentic scan analyzer is not available for project', agentic_actions.first)
          return ServiceResponse.success(payload: { triggered: [] })
        end

        unless ::Feature.enabled?(:autonomous_service_account_execution, project)
          log_skip('Autonomous service account execution is disabled for project', agentic_actions.first)
          return ServiceResponse.success(payload: { triggered: [] })
        end

        triggered = agentic_actions.filter_map { |action| run_action(action) }

        ServiceResponse.success(payload: { triggered: triggered })
      end

      private

      def run_action(action)
        flow_reference = SCAN_TYPE_TO_FLOW_REFERENCE[action[:scan].to_s]

        # System lookup: no user acts on a scheduled scan, and ExecuteService authorizes the
        # service account against the consumer it returns.
        consumer = ::Ai::Catalog::ItemConsumer.find_by_project_and_flow_reference(project, flow_reference)
        return log_skip('No foundational-flow consumer provisioned for agentic scan', action) unless consumer

        provisioned = ::Security::SecurityOrchestrationPolicies::ProvisionAgenticScanTriggerService.new(
          project: project,
          params: { item_consumer: consumer, scan: action[:scan], policy_name: params[:policy_name] }
        ).execute

        if provisioned.error?
          return log_skip(provisioned.message, action,
            Labkit::Fields::ERROR_MESSAGE => provisioned.payload[:error_message])
        end

        trigger = provisioned.payload[:trigger]
        service_account = trigger.autonomous_service_account

        if reconcile_service_account_role(trigger, consumer)
          return log_skip('Service account holds more access than the flow, and could not be adjusted', action)
        end

        eligibility = ::Ai::FlowTriggers::AutonomousServiceAccountEligibilityValidator.new(service_account, project)
        unless eligibility.valid?
          return log_skip('Service account is not eligible for agentic scan', action,
            Labkit::Fields::ERROR_MESSAGE => eligibility.errors.full_messages.join(', '))
        end

        result = ::Ai::Catalog::Flows::ExecuteService.new(
          project: project,
          current_user: service_account,
          params: {
            item_consumer: consumer,
            service_account: service_account,
            execute_workflow: true,
            event_type: 'sidekiq_worker',
            trigger_source: :scheduled,
            trigger_flow_trigger_id: trigger.id,
            trigger_event_type: :security_policy,
            source_branch: params[:branch],
            user_prompt: scheduled_prompt(action)
          }
        ).execute

        unless result.success?
          return log_skip('Scheduled agentic scan failed to start', action,
            Labkit::Fields::ERROR_MESSAGE => result.message, Labkit::Fields::ERROR_TYPE => result.reason)
        end

        flow_reference
      end

      def reconcile_service_account_role(trigger, consumer)
        ::Ai::FlowTriggers::SyncAutonomousServiceAccountRoleService.new(
          project: project, item_consumer: consumer, service_account_id: trigger.autonomous_service_account_id
        ).execute.payload[:excess_access]
      end

      def scheduled_prompt(action)
        {
          source: "scan_execution_policy",
          scan: action[:scan],
          branch: params[:branch],
          policy_name: params[:policy_name]
        }.to_json
      end

      def log_skip(message, action, **extra)
        ::Gitlab::AppJsonLogger.warn(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => "#{message}; skipping",
            Labkit::Fields::GL_PROJECT_ID => project.id,
            scan: action[:scan],
            foundational_flow_reference: SCAN_TYPE_TO_FLOW_REFERENCE[action[:scan].to_s],
            policy_name: params[:policy_name],
            **extra
          )
        )

        nil
      end
    end
  end
end
