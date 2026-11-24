# frozen_string_literal: true

module Ai
  module Catalog
    class ExecuteWorkflowService
      include Gitlab::Utils::StrongMemoize

      WORKFLOW_ENVIRONMENT = 'web'
      AGENT_PRIVILEGES = [
        DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
        DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
        DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
        DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
        DuoWorkflows::Workflow::AgentPrivileges::USE_GIT,
        DuoWorkflows::Workflow::AgentPrivileges::RUN_MCP_TOOLS,
        DuoWorkflows::Workflow::AgentPrivileges::START_FLOWS
      ].freeze

      def initialize(current_user, params)
        @current_user = current_user
        @json_config = params[:json_config]
        @container = params[:container]
        @service_account = params[:service_account]
        @flow_definition = params[:flow_definition] || determine_workflow_definition
        @flow_config_id = params[:flow_config_id]
        @flow_config_schema_version_param = params[:flow_config_schema_version]
        @flow_version = params[:flow_version]
        @source_branch = params[:source_branch]
        @additional_context = params[:additional_context]
        @event_type = params[:event_type]
        @triggering_conversation = params[:triggering_conversation]
        @issue_id = params[:issue_id]
        @messaging_callback_context = params[:messaging_callback_context]
        @merge_request_id = params[:merge_request_id]
        @resource = params[:resource]
        @source_type = params[:source_type]
        @source_link = params[:source_link]
        @title = params[:title]
        @trigger_source = params[:trigger_source]
        @trigger_flow_trigger_id = params[:trigger_flow_trigger_id]
        @trigger_flow_schedule_id = params[:trigger_flow_schedule_id]
        @parent_workflow = params[:parent_workflow]
        @workflow_attributes = params[:workflow_attributes]
        @trigger_event_type = params[:trigger_event_type]
        @resume_context = params[:resume_context]
        @runtime = params[:runtime]
        @provision_membership = params.fetch(:provision_membership, false)
        existing_workflow = @resume_context&.fetch(:existing_workflow, nil)
        @goal = params[:goal] || existing_workflow&.goal
        @item_version = params[:item_version] || existing_workflow&.ai_catalog_item_version
        @item = item_version&.item
      end

      def execute
        return validate unless validate.success?

        workflow = if @resume_context
                     @resume_context[:existing_workflow]
                   else
                     workflow_result = create_workflow
                     if workflow_result.error?
                       return error(workflow_result[:message], payload: workflow_result.payload,
                         http_status: workflow_result.http_status, reason: workflow_result.payload[:reason])
                     end

                     workflow_result.payload[:workflow]
                   end

        start_result = start_workflow_execution(workflow)
        # The workflow goes back with the error so a messaging caller can claim its
        # delivery; otherwise the stuck-workflow reaper reports the failure again.
        if start_result.error?
          return error(start_result[:message], payload: { workflow: workflow }, reason: start_result.reason,
            http_status: (:unprocessable_entity if start_result.reason == :repository_empty))
        end

        ServiceResponse.success(
          payload: {
            workflow: workflow,
            workload_id: start_result.payload[:workload_id],
            flow_config: json_config.to_yaml
          }
        )
      end

      private

      attr_reader :current_user, :json_config, :container, :goal, :item, :item_version, :service_account

      def error(message, payload: {}, http_status: nil, reason: nil)
        # rubocop:disable Gitlab/ServiceResponse -- This endpoint chain maps http_status to the REST response status.
        ServiceResponse.error(message: Array(message), payload: payload, http_status: http_status, reason: reason)
        # rubocop:enable Gitlab/ServiceResponse
      end

      def validate
        return error('You have insufficient permissions') unless allowed?
        return error('JSON config is required') unless json_config.present? || foundational_flow?
        return error('Goal is required') unless goal.present?

        ServiceResponse.success
      end
      strong_memoize_attr :validate

      def create_workflow
        workflow_params = {
          goal: goal,
          workflow_definition: @flow_definition,
          ai_catalog_item_version_id: item_version&.id,
          environment: resolved_environment,
          agent_privileges: resolved_agent_privileges,
          pre_approved_agent_privileges: resolved_pre_approved_agent_privileges,
          allow_agent_to_request_user: false,
          service_account: service_account,
          title: @title.presence&.truncate(Ai::DuoWorkflows::Workflow::TITLE_MAX_LENGTH)
        }

        workflow_params[:issue_id] = @issue_id if @issue_id
        workflow_params[:messaging_callback_context] = @messaging_callback_context if @messaging_callback_context
        workflow_params[:merge_request_id] = @merge_request_id if @merge_request_id
        workflow_params[:resource] = @resource if @resource
        workflow_params[:source_type] = @source_type if @source_type
        workflow_params[:source_link] = @source_link if @source_link
        # Explicit attributes win over the defaults above, e.g. a restart carrying
        # over the original session's privileges and trigger.
        workflow_params.merge!(@workflow_attributes) if @workflow_attributes.present?

        # Trigger metadata for triggered flows; must be set at creation time because
        # trigger_source and trigger_event_type are attr_readonly on Workflow.
        workflow_params.merge!(trigger_metadata_params)
        workflow_params[:parent_workflow] = @parent_workflow if @parent_workflow

        ::Ai::DuoWorkflows::CreateWorkflowService.new(
          container: container,
          current_user: current_user,
          params: workflow_params,
          **(started_flow ? { started_flow: started_flow } : {})
        ).execute
      end

      def started_flow
        return if @flow_config_id.blank?

        {
          flow_config_id: @flow_config_id,
          flow_config_schema_version: @flow_config_schema_version_param,
          flow_version: @flow_version
        }
      end

      def trigger_metadata_params
        {
          trigger_source: @trigger_source,
          trigger_flow_trigger_id: @trigger_flow_trigger_id,
          trigger_flow_schedule_id: @trigger_flow_schedule_id,
          trigger_event_type: @trigger_event_type
        }.compact
      end

      # The runtime reads the flow config from the session, which create_workflow recorded via started_flow.
      def start_workflow_execution(workflow)
        runtime = run_runtime(workflow)

        # On CI, StartWorkflowService (and ResumeWorkflowService) enforce "Allow flow execution". Workhorse has
        # no equivalent, so a Workhorse start or resume checks it here, with the same ability the `:execute`
        # endpoint uses to let a Workhorse run act as the flow's service account.
        if runtime == :workhorse && !Ability.allowed?(current_user, :execute_duo_workflow_in_ci, workflow)
          return ServiceResponse.error(message: 'Can not execute workflow', reason: :feature_unavailable)
        end

        # The Sidekiq job enqueued inside inherits this context, so the turn's log lines carry the session id.
        ::Gitlab::ApplicationContext.with_context(duo_workflow_id: workflow.id.to_s) do
          ::Ai::DuoWorkflows::ExecuteRunService.new(
            workflow,
            event: run_event(workflow),
            # The caller's raw override, so ExecuteRunService rejects one that doesn't resolve.
            runtime: (@runtime unless @resume_context),
            context: trigger_context_params.merge(additional_context: @additional_context),
            source_branch: @source_branch,
            provision_membership: @provision_membership
          ).execute
        end
      end

      # Resolved with ExecuteRunService's rule, so the check above and the run agree. Only a
      # start takes the caller's override; a resume follows the session's last runtime.
      def run_runtime(workflow)
        ::Ai::DuoWorkflows::ExecuteRunService.runtime_for_session(
          workflow, override: (@runtime unless @resume_context)
        )
      end

      def run_event(workflow)
        return { type: :input, text: workflow.goal } unless @resume_context

        ::Ai::DuoWorkflows::RunEvent.for_resume(
          workflow, approved: @resume_context[:human_approval], message: @resume_context[:human_message]
        )
      end

      # A foundational flow's `mention` trigger advertises the flow's respond
      # path, whose reply is posted by the messaging adapter
      # (Ai::Messaging::CallbackWorker) when the workflow completes. Without an
      # adapter binding nothing delivers the flow's final answer, so withhold
      # the trigger context and let the flow take its default route (e.g.
      # Security Review runs a full review) instead of producing a reply that
      # is never posted.
      def trigger_context_params
        return {} if foundational_flow? && @event_type.to_s == 'mention' && @messaging_callback_context.blank?

        { event_type: @event_type, triggering_conversation: @triggering_conversation }
      end

      def resolved_environment
        declared_flow&.environment.presence || WORKFLOW_ENVIRONMENT
      end

      def determine_workflow_definition
        ::Ai::DuoWorkflows::Workflow::AI_CATALOG_AGENT_FLOW_TYPE
      end

      def resolved_agent_privileges
        declared_flow ? declared_flow.agent_privileges : AGENT_PRIVILEGES
      end

      def resolved_pre_approved_agent_privileges
        declared_flow ? declared_flow.pre_approved_agent_privileges : AGENT_PRIVILEGES
      end

      def declared_flow
        ::Ai::Catalog::FoundationalFlow.find_by_reference(@flow_definition)
      end
      strong_memoize_attr :declared_flow

      def allowed?
        return false unless Ability.allowed?(current_user, :execute_ai_catalog_item, container)
        return false if item_blocked_by_namespace_restriction?
        return false if outside_restricted_hierarchy?

        true
      end

      def item_blocked_by_namespace_restriction?
        return false if item.nil?

        item.blocked_by_namespace_restriction?(container.root_ancestor)
      end

      def outside_restricted_hierarchy?
        item.present? && item.outside_restricted_hierarchy?(container)
      end

      def foundational_flow?
        ::Ai::Catalog::Item.with_foundational_flow_reference(@flow_definition).present?
      end
      strong_memoize_attr :foundational_flow?
    end
  end
end
