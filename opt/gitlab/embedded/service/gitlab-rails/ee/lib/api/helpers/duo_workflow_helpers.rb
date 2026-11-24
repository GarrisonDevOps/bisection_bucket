# frozen_string_literal: true

module API
  module Helpers
    module DuoWorkflowHelpers
      include Gitlab::Utils::StrongMemoize

      # Untranslated on purpose: MCP tools match this against the serialized REST body, which is localized per request.
      COMPOSITE_IDENTITY_SERVICE_ACCOUNT_MESSAGE =
        'A composite identity service account is required to start this workflow.'

      INVALID_GOAL_MESSAGE = 'Invalid goal'

      INSUFFICIENT_CREDITS_MESSAGE =
        'session failed to start due to insufficient GitLab credits. Purchase more credits to continue.'

      def push_ai_gateway_headers(scope: nil, subject: current_user)
        governing_namespace = current_user.governing_namespace(scope)

        push_feature_flags(governing_namespace)

        Gitlab::AiGateway.public_headers(
          user: current_user,
          ai_feature_name: :duo_workflow,
          unit_primitive_name: :duo_agent_platform,
          organization_id: governing_namespace&.organization_id,
          governing_namespace_id: governing_namespace&.id,
          subject: subject
        ).each do |name, value|
          header(name, value)
        end
      end

      def push_feature_flags(root_namespace = nil, feature_setting_name: nil)
        Gitlab::AiGateway.push_feature_flag(:expanded_ai_logging, current_user)
        Gitlab::AiGateway.push_feature_flag(:duo_agentic_chat_openai_gpt_5, current_user)
        Gitlab::AiGateway.push_feature_flag(:use_generic_gitlab_api_tools, current_user)
        Gitlab::AiGateway.push_feature_flag(:ai_prompt_scanning, current_user)
        Gitlab::AiGateway.push_feature_flag(:dap_web_search, current_user)
        Gitlab::AiGateway.push_feature_flag(:dap_tool_image_input, current_user)
        Gitlab::AiGateway.push_feature_flag(:dependency_bump_web_search, current_user)
        Gitlab::AiGateway.push_feature_flag(:ai_context_compaction, current_user)
        Gitlab::AiGateway.push_feature_flag(:ai_model_release, current_user)
        Gitlab::AiGateway.push_feature_flag(:duo_chat_clarification_question_tool, current_user)
        Gitlab::AiGateway.push_feature_flag(:software_development_flow_registry, current_user)
        Gitlab::AiGateway.push_feature_flag(:dap_parallel_subagents, current_user)
        Gitlab::AiGateway.push_feature_flag(:dap_for_each, current_user)
        Gitlab::AiGateway.push_feature_flag(:dap_workspace_agents, current_user)
        Gitlab::AiGateway.push_feature_flag(:duo_chat_tool_call_limits, current_user)

        # Intelligent model routing is being trialled on the Duo Developer flow only.
        if feature_setting_name == :duo_developer
          Gitlab::AiGateway.push_feature_flag(:duo_developer_model_routing, current_user)
        end

        return unless root_namespace

        Gitlab::AiGateway.push_feature_flag(:duo_agentic_chat_prefer_mcp_tools, root_namespace)
      end

      def find_item_consumer!(consumer_id, project)
        consumer = ::Ai::Catalog::ItemConsumer.find(consumer_id)

        forbidden!('Agent or flow is not enabled for this project') unless consumer.project_id == project.id

        consumer
      rescue ActiveRecord::RecordNotFound
        not_found!('Enabled agent or flow was not found for this project.')
      end

      # Ai::Catalog::ExecuteWorkflowService wraps its error message in an array
      # (other callers depend on that contract), so unwrap it here for the plain
      # string the repository_empty response body promises.
      def render_catalog_flow_error!(result)
        return unless result.error?

        if result.reason == :repository_empty
          render_structured_api_error!(
            { 'message' => Array(result.message).join(' '), 'reason' => 'repository_empty' },
            :unprocessable_entity
          )
        end

        render_api_error!(result.message, :unprocessable_entity) if result.http_status == :unprocessable_entity

        bad_request!(catalog_flow_error_message(result))
      end

      def catalog_flow_error_message(result)
        return INSUFFICIENT_CREDITS_MESSAGE if result.http_status == :payment_required

        Array(result.message).join(' ')
      end

      def forbidden_if_identity_verification_required!(container)
        return unless current_user.dap_identity_verification_required?(container)

        forbidden!(s_('DuoAgentsPlatform|Identity verification is required to use GitLab Duo Agent Platform'))
      end

      # Blocks the Workflow row and its "agent session started" system note from ever being
      # created for an empty repository, rather than letting the workload fail after the fact.
      def require_repository_for_flow!(container)
        return unless params[:start_workflow].present?
        return unless container.is_a?(Project) && container.empty_repo?

        render_structured_api_error!(
          {
            'message' => ::Ai::FoundationalFlowMessages.repository_empty_error,
            'reason' => 'repository_empty'
          },
          :unprocessable_entity
        )
      end

      # Mirrors ExecuteService#allowed? so the repository guard only runs for callers the
      # service would let execute the flow; everyone else gets its permission error unchanged.
      def can_execute_catalog_item?(consumer, container)
        Ability.allowed?(current_user, :execute_ai_catalog_item, consumer.authorization_subject(project: container))
      end

      def forbidden_unless_usage_quota_available!(namespace)
        quota_check_response = ::Ai::UsageQuotaService.new(user: current_user, namespace: namespace).execute
        return unless quota_check_response.error?

        message = case quota_check_response.reason
                  when :usage_quota_exceeded
                    "USAGE_QUOTA_EXCEEDED: #{quota_check_response.message}"
                  when :usage_billing_forbidden
                    "USAGE_BILLING_FORBIDDEN: #{quota_check_response.message}"
                  when :namespace_missing
                    ::Ai::FoundationalFlowMessages.namespace_missing_error(current_user)
                  else
                    quota_check_response.message
                  end

        forbidden!(message)
      end

      def find_workflow_namespace!(id)
        namespace = find_namespace(id)

        if namespace.is_a?(::Group) && current_user.authorized_groups.id_in(namespace.id).exists?
          check_organization_maintenance_mode_for!(namespace)
          return namespace
        end

        resolve_namespace_access!(namespace)
      end

      def container_access_allowed?(container)
        if container.is_a?(Project)
          Ability.allowed?(current_user, :read_project, container)
        else
          Ability.allowed?(current_user, :read_group, container)
        end
      end

      # Resolves the namespace ID from request params/headers.
      # The IDE sends namespace_id of the project's immediate group via header,
      # while the web agentic chat UI sends it as a query param.
      def request_namespace_id
        params[:root_namespace_id].presence ||
          params[:namespace_id].presence ||
          headers['X-Gitlab-Namespace-Id'].presence
      end

      # Resolves the namespace object from request params/headers.
      # Returns nil if namespace is not found or the user lacks read access.
      def find_request_namespace
        id = request_namespace_id
        return unless id

        namespace = find_namespace(id)
        return unless namespace &&
          Ability.allowed?(current_user, :read_group, namespace, composite_identity_check: false)

        namespace
      end

      def start_workflow_params(workflow_id, container:, service_account: nil, workflow_definition: nil)
        workflow_definition ||= params[:workflow_definition]

        {
          goal: params[:goal],
          workflow_id: workflow_id,
          source_branch: params[:source_branch].presence || resolve_source_branch(workflow_definition, container),
          additional_context: params[:additional_context],
          workflow_metadata: Gitlab::DuoWorkflow::Client.metadata(current_user,
            namespace: find_request_namespace || container.root_ancestor,
            project: find_project(params[:project_id].presence)).to_json,
          **langsmith_trace_params,
          **foundational_flow_report_artifacts(workflow_definition)
        }.merge(
          workflow_credential_params(
            container: container,
            service_account: service_account,
            workflow_definition: workflow_definition,
            workflow_id: workflow_id
          )
        )
      end

      # Pass `workflow:` when resuming, so the run keeps the session's flow version.
      def workflow_credential_params(container:, service_account:, workflow_definition:, workflow_id:, workflow: nil)
        resolved_service_account = resolve_start_workflow_service_account(service_account, container)
        foundational_flow_start_params = workflow&.foundational_flow_params ||
          ::Ai::DuoWorkflows::FoundationalFlowStartParamsResolver.call(
            workflow_definition, container, user: current_user
          )
        workflow_context_service = workflow_context_generation_service(
          container: container, service_account: resolved_service_account, workflow_definition: workflow_definition,
          workflow_id: workflow_id
        )

        oauth_token_result = workflow_context_service.generate_oauth_token_with_composite_identity_support(
          expires_in: ::Ai::DuoWorkflows::WorkloadCredential::EXPIRES_IN
        )

        if oauth_token_result.error?
          render_api_error!(oauth_token_result[:message], oauth_token_result[:http_status] || :forbidden)
        end

        workflow_token_result = workflow_context_service.generate_workflow_token(
          flow_config_id: foundational_flow_start_params[:flow_config_id],
          flow_version: foundational_flow_start_params[:flow_version],
          flow_config_schema_version: foundational_flow_start_params[:flow_config_schema_version],
          workflow_id: workflow_id
        )
        handle_workflow_token_error(workflow_token_result) if workflow_token_result.error?

        {
          workflow_oauth_token: oauth_token_result[:oauth_access_token].plaintext_token,
          workflow_service_token: workflow_token_result[:token],
          service_account: resolved_service_account,
          duo_agent_platform_feature_setting: workflow_context_service.duo_agent_platform_feature_setting
        }.merge(foundational_flow_start_params)
      end

      # Name-started foundational flows must declare their report artifacts the same way
      # catalog-consumer starts do, or their reports are never collected and ingested.
      def foundational_flow_report_artifacts(workflow_definition)
        # rubocop:disable Gitlab/Ai/AvoidFoundationalFlowStringLookup -- dynamic, request-provided reference
        reports = ::Ai::Catalog::FoundationalFlow.find_by_reference(workflow_definition)&.report_artifacts
        # rubocop:enable Gitlab/Ai/AvoidFoundationalFlowStringLookup
        reports.present? ? { report_artifacts: reports } : {}
      end

      # `client_executed` mirrors FlowExecutionAuthorizer#client_executed?, which runs
      # later: the caller runs the flow unless it asks for a CI run or names a consumer.
      def validate_flow_start_request!(workflow_definition, container, client_executed:)
        result = request_foundational_flow(workflow_definition)&.validate_start_request(
          container: container,
          goal: params[:goal],
          additional_context: params[:additional_context],
          client_executed: client_executed
        )
        return unless result

        bad_request!(goal_error_message(result, container)) if result.error?

        params[:goal] = result.payload[:goal]
      end

      # Goal error messages describe the merge request. `workflows.rb` checks goals
      # before flow authorization, so callers who cannot read merge requests get a
      # constant message.
      def goal_error_message(result, container)
        return result.message unless container.is_a?(::Project)
        return result.message if Ability.allowed?(current_user, :read_merge_request, container)

        INVALID_GOAL_MESSAGE
      end

      def resolve_source_branch(workflow_definition, container)
        return unless container.is_a?(::Project)

        request_foundational_flow(workflow_definition)
          &.resolve_source_branch_for(project: container, goal: params[:goal])
      end

      # rubocop:disable Gitlab/Ai/AvoidFoundationalFlowStringLookup -- the reference comes from the request
      def request_foundational_flow(workflow_definition)
        ::Ai::Catalog::FoundationalFlow[workflow_definition]
      end
      # rubocop:enable Gitlab/Ai/AvoidFoundationalFlowStringLookup

      def langsmith_trace_params
        return {} unless headers['Langsmith-Trace'].present?

        { langsmith_trace: headers['Langsmith-Trace'] }
      end

      def workflow_context_generation_service(
        container: nil, service_account: nil, workflow_definition: nil, workflow_id: nil)
        workflow_definition ||= params[:workflow_definition]

        ::Ai::DuoWorkflows::WorkflowContextGenerationService.new(
          current_user: current_user,
          organization: container&.organization || ::Current.organization,
          workflow_definition: workflow_definition,
          service_account: resolve_service_account(service_account),
          container: container,
          surface: ::Ai::ToolRules::GovernanceSurface.from_environment(
            params[:environment], container: container, workflow_definition: workflow_definition
          ),
          workflow_id: workflow_id
        )
      end

      def resolve_start_workflow_service_account(service_account, container)
        unless enforce_composite_identity_for_api_started_workflows?(container)
          return resolve_service_account(service_account)
        end

        service_account ||= service_account_from_composite_identity

        validate_start_workflow_service_account!(service_account)
      end

      def enforce_start_workflow_service_account(service_account, container, consumer: nil)
        return service_account unless params[:start_workflow].present?
        return service_account unless enforce_composite_identity_for_api_started_workflows?(container)
        # Unauthorized catalog callers must get the regular catalog permission error,
        # not a response that reveals the mapped account's composite identity setting.
        return service_account if consumer && !Ability.allowed?(current_user, :execute_ai_catalog_item, consumer)

        resolve_start_workflow_service_account(service_account, container)
      end

      def validate_start_workflow_service_account!(service_account)
        forbidden!(COMPOSITE_IDENTITY_SERVICE_ACCOUNT_MESSAGE) unless service_account&.composite_ai_service_account?

        service_account
      end

      def enforce_composite_identity_for_api_started_workflows?(container)
        Feature.enabled?(:enforce_composite_identity_for_api_started_workflows, container.root_ancestor)
      end

      def resolve_service_account(service_account = nil)
        service_account || service_account_from_composite_identity || duo_workflow_service_account
      end

      def duo_workflow_service_account
        project = find_project(params[:project_id]) if params[:project_id]
        organization = project&.organization || ::Current.organization
        service_account = ::Ai::Setting.for_organization_read_only(organization).duo_workflow_service_account_user
        return unless service_account

        ::Ai::ServiceAccountMemberAddService.new(project, service_account).execute if project
        service_account
      end

      def service_account_from_composite_identity
        service_account = ::Gitlab::Auth::Identity.resolve_composite_identity_actor(current_user)

        service_account if service_account&.service_account?
      end

      # Guards internal writeback endpoints that only Duo Workflow Service may call.
      def verify_flow_composite_identity!(flow, container)
        return if flow_service_account?(flow, container)

        forbidden!('This endpoint can only be accessed by Duo Workflow Service')
      end

      # Composite identity: the service account acts on behalf of a human user, so
      # `current_user` is the human and the resolved actor is the flow's own account.
      def flow_service_account?(flow, container)
        service_account = service_account_from_composite_identity
        return false unless service_account

        resolved = ::Ai::Catalog::ItemConsumers::ResolveServiceAccountService.new(
          container: container,
          item: flow.catalog_item
        ).execute

        return false if resolved.error?

        resolved.payload.fetch(:service_account).id == service_account.id
      end

      def handle_workflow_token_error(result)
        message = result[:message]

        if message.include?("USAGE_QUOTA_EXCEEDED")
          message = "You don't have enough GitLab Credits to run this flow. " \
            "Contact your administrator for more credits."
          render_api_error!(message, :forbidden)
        else
          render_api_error!(message, :bad_request)
        end
      end

      # Authorization and the service account come from one call so they cannot derive
      # from different classifications.
      def authorize_flow_execution!(
        workflow_params, container, caller_can_execute:, start_workflow:, item_consumer_id:)
        result = ::Ai::DuoWorkflows::FlowExecutionAuthorizer.new(
          current_user: current_user,
          container: container,
          workflow_definition: workflow_params[:workflow_definition],
          start_workflow: start_workflow,
          item_consumer_id: item_consumer_id,
          caller_can_execute: caller_can_execute
        ).execute

        forbidden!(result.message) if result.error?

        service_account = result.payload[:service_account]
        workflow_params[:service_account] = service_account if service_account
        canonical_definition = result.payload[:workflow_definition]
        workflow_params[:workflow_definition] = canonical_definition if canonical_definition

        result.payload[:execution]
      end

      def resolve_workflow_definition(consumer)
        params[:workflow_definition] || consumer&.item&.foundational_flow_reference
      end

      # Scoped to the request's project so a goal can't pull another project's
      # vulnerability (and its raw secret) into this workflow.
      def vulnerability_from_goal
        project = find_project(params[:project_id].presence)
        return unless project.is_a?(::Project)

        project.vulnerabilities.find_by_id(params[:goal])
      end
      strong_memoize_attr :vulnerability_from_goal

      # Creates the Vulnerabilities::TriggeredWorkflow join row that links a
      # user-initiated Duo Workflow back to its target vulnerability so the row
      # surfaces in `Vulnerability.aiWorkflows`. The flag-driven workers create
      # this row themselves; the user-initiated API path did not, until now.
      def link_vulnerability_to_user_triggered_workflow(workflow)
        return unless workflow

        workflow_name = ::Vulnerabilities::TriggeredWorkflow::WORKFLOW_DEFINITIONS_TO_NAMES[workflow.workflow_definition]
        return unless workflow_name

        finding = vulnerability_from_goal&.finding
        return unless finding

        ::Vulnerabilities::TriggeredWorkflow.create!(
          vulnerability_occurrence_id: finding.id,
          workflow_id: workflow.id,
          workflow_name: workflow_name
        )
      rescue ActiveRecord::RecordInvalid => error
        ::Gitlab::ErrorTracking.track_exception(
          error,
          vulnerability_id: vulnerability_from_goal&.id,
          workflow_id: workflow&.id
        )
        nil
      end
    end
  end
end
