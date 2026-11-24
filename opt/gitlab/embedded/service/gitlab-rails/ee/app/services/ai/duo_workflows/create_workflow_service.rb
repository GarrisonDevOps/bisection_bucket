# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CreateWorkflowService
      include ::Services::ReturnServiceResponses
      include ::Gitlab::Loggable
      include ::Gitlab::Utils::StrongMemoize
      include Concerns::LinkArtifact
      include Concerns::WorkflowEventTracking
      include Concerns::GovernanceResolution

      CouldNotDropWorkflowError = Class.new(StandardError)
      MAX_DENIED_TOOLS_NAMED = 5
      UNREADY_DROP_REASONS = {
        no_eligible_runner: 'preconditions_not_met',
        namespace_ci_minutes_used_up: 'compute_minutes_used_up',
        could_not_prepare_session: 'could_not_prepare_session'
      }.freeze
      DEFAULT_MAX_ACTIVE_BL_SECURITY_SCANS_PER_ROOT_NAMESPACE = 20
      # Longer than CleanStuckWorkflowsService takes to drop an idle session; bounds the count query.
      BL_SECURITY_SCAN_ACTIVITY_WINDOW = 1.hour

      # `execution` is a FlowExecutionAuthorizer::Classification. Anything else,
      # nil or a raw value, gets the strictest access check.
      # `started_flow` is the flow config the caller already picked, such as the @GitLabDuo
      # mention assistant under code_review/v1 or the flow a Code Review depth selects.
      def initialize(
        container:, current_user:, params:, execution: nil, privileges_from_client: false, started_flow: nil
      )
        @container = container || ::Ai::UserAuthorizer.for(current_user).default_duo_namespace
        @current_user = current_user
        @execution = execution
        @started_flow = started_flow
        # Caller-supplied privileges are clamped to governance; app-set ones are not.
        # A client-facing caller that omits this skips the clamp and silently reopens
        # https://gitlab.com/gitlab-org/gitlab/-/issues/618863, the way app-set callers do.
        @privileges_from_client = privileges_from_client
        # Remove ids to avoid confusion - @container determines the workflow scope, not raw IDs
        @params = params.except(:namespace_id, :project_id)
      end

      def execute
        unless @container.is_a?(::Project) || @container.is_a?(::Namespace)
          return error('container must be a Project or Namespace', :bad_request)
        end

        resolve_agent_privileges

        credit_check_response = check_usage_quota

        if credit_check_response.error?
          # http status should not be part of Service, but needs significant refactoring in the callers of
          # CreateWorkflowService.execute
          http_status = http_status_for_quota_error(credit_check_response.reason)
          message = enriched_error_message(credit_check_response)
          return error(message, http_status, pass_back: { reason: credit_check_response.reason })
        end

        response = pre_create_check
        return response if response&.error?

        log_concurrent_session_count
        log_goal_size

        workflow = Ai::DuoWorkflows::Workflow.new(workflow_attributes)

        in_flight_check = CheckInFlightSessionService.new(workflow: workflow)
        save_error = in_flight_check.execute { save_workflow(workflow) }

        return save_error if save_error

        link_artifact(workflow, link_type: :source) { workflow.work_item }
        link_artifact(workflow, link_type: :source) { workflow.merge_request }
        link_artifact(workflow, link_type: :source) { resolve_source_pipeline(workflow) }

        unless workflow.triggered_by_verification?
          Ai::DuoWorkflows::GenerateWorkflowTitleWorker.perform_async(workflow.id)
        end

        identity = mcp_flow_identity(workflow)
        track_workflow_event("agent_platform_session_created", workflow,
          source: workflow.source_type, additional_properties: identity.merge(mcp_client_properties(workflow)))
        log_mcp_session_created(workflow, identity) if workflow.source_mcp?

        audit_workflow_creation(workflow)

        create_workflow_system_note(workflow)

        created_workflow_error = post_create_error(workflow)
        return created_workflow_error if created_workflow_error

        in_flight_check.supersede_live_sessions

        Ai::DuoWorkflows::SyncSessionArtifactWorker.enqueue(workflow)

        enqueue_child_session_card(workflow)

        success(workflow: workflow)
      end

      def workflow_attributes
        base_params.merge(
          user: @current_user,
          # This is needed until the column can be safely removed
          # https://gitlab.com/gitlab-org/gitlab/-/work_items/627332
          incremental_checkpoints_enabled: true,
          **container_attributes,
          **noteable_attributes,
          **service_account_attributes,
          **execution_mode_attributes,
          **source_type_attributes,
          **parent_workflow_attributes,
          flow_metadata_json: started_flow_metadata
        )
      end

      private

      # Recorded once for flows Rails runs, so a resume runs the flow this session started
      # with even after a flag or default changes what the resolver returns.
      def started_flow_metadata
        flow = @started_flow.presence || resolved_started_flow

        ::Ai::DuoWorkflows::FlowMetadata.started(flow)
      end

      # A client-executed session runs the flow its client picks (for example the Duo CLI's
      # interactive or goal flow), which the resolver can't know. Recording nothing lets the
      # first checkpoint store the flow the session actually ran.
      def resolved_started_flow
        return if client_executed?

        ::Ai::DuoWorkflows::FoundationalFlowStartParamsResolver.call(workflow_definition, @container,
          user: @current_user)
      end

      def mcp_flow_identity(workflow)
        return {} unless workflow.source_mcp?

        ::Ai::Catalog::Tracking::WorkflowIdentityPropertiesBuilder.new(workflow).to_h
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
        {}
      end

      def log_mcp_session_created(workflow, identity)
        ::Gitlab::Mcp::Logger.build.conditional_info(
          @current_user,
          message: 'Duo session created over MCP',
          event_name: 'duo_session_created',
          ai_component: 'mcp_server',
          source_type: workflow.source_type,
          **mcp_client_properties(workflow),
          ::Labkit::Fields::DUO_WORKFLOW_ID => workflow.id,
          **identity
        )
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
      end

      # Same names as the MCP tool call events and log lines, so they can be joined.
      def mcp_client_properties(workflow)
        { mcp_client_name: workflow.source_client_name, mcp_client_version: workflow.source_client_version }.compact
      end

      # `parent_workflow` is only accepted from server-side callers, and only takes effect behind the flag.
      def caller_context
        parent_workflow = @params[:parent_workflow]
        return unless parent_workflow
        return unless Feature.enabled?(:ai_flow_trigger_chaining, @container.root_ancestor)

        ::Ai::FlowTriggers::CallerContext.new(parent_workflow: parent_workflow)
      end
      strong_memoize_attr :caller_context

      def parent_workflow_attributes
        return {} unless caller_context

        { parent_workflow: caller_context.parent_workflow, trigger_source: :flow }
      end

      def enqueue_child_session_card(workflow)
        return unless workflow.parent_workflow_id
        return unless ::Ai::Messaging::ChildSession.relayed?(workflow)

        ::Ai::Messaging::ChildSessionCardWorker.perform_async(workflow.id)
      end

      def check_caller_context
        return unless caller_context

        unless @params[:trigger_source].nil? || @params[:trigger_source].to_s == 'flow'
          return chain_error('a workflow with a parent must be triggered by a flow', :invalid_trigger_source)
        end

        if root_namespace_check_enabled? && !caller_context.same_root_namespace?(@container)
          return chain_error('parent workflow belongs to a different top-level namespace',
            :parent_workflow_namespace_mismatch)
        end

        return chain_error('workflow chain is too deep', :trigger_depth_exceeded) if caller_context.depth_exceeded?
        return if caller_context.root_human

        chain_error('workflow chain was not started by a human user', :chain_root_not_human)
      end

      def root_namespace_check_enabled?
        Feature.enabled?(:ai_flow_trigger_chaining_root_namespace_check, @container.root_ancestor)
      end

      # Locking the root serializes every creation in the chain, which covers both caps.
      # NO KEY UPDATE still lets running workflows insert rows that reference the root.
      def save_workflow(workflow)
        return workflow_save_error(workflow) unless caller_context

        caller_context.root_workflow.with_lock('FOR NO KEY UPDATE') do
          if caller_context.breadth_exceeded?
            chain_error('workflow started too many workflows', :trigger_breadth_exceeded)
          elsif caller_context.chain_size_exceeded?
            chain_error('workflow chain started too many workflows', :trigger_chain_size_exceeded)
          else
            workflow_save_error(workflow)
          end
        end
      end

      def workflow_save_error(workflow)
        return if workflow.save

        error(workflow.errors.full_messages.join(', '), :bad_request)
      end

      def chain_error(message, reason)
        error(message, :forbidden, pass_back: { reason: reason })
      end

      def audit_workflow_creation(workflow)
        audit_context = {
          name: 'duo_session_created',
          author: @current_user,
          scope: workflow.project || workflow.namespace,
          target: workflow,
          target_details: "#{'[Verification Run] ' if workflow.triggered_by_verification?}" \
            "#{workflow.workflow_definition} session #{workflow.id}",
          message: 'Created Duo session'
        }
        audit_context[:additional_details] = { verification_run: true } if workflow.triggered_by_verification?

        ::Gitlab::Audit::Auditor.audit(audit_context)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
      end

      # A verification run is a synthetic diagnostic, not real user activity - gating it on
      # remaining credits would block the check for exactly the customers who need it.
      def check_usage_quota
        return ServiceResponse.success if verification_run?

        namespace = @container.is_a?(::Project) ? @container.namespace : @container
        Ai::UsageQuotaService.new(
          user: @current_user,
          namespace: namespace,
          workflow_definition: workflow_definition
        ).execute
      end

      def log_concurrent_session_count
        max = ::Ai::DuoWorkflows::Workflow::MAX_CONCURRENT_SESSIONS_PER_USER
        active_count = ::Ai::DuoWorkflows::Workflow
          .for_user(@current_user.id)
          .in_status_group(:active)
          .count

        return unless active_count >= max

        Gitlab::AppLogger.warn(
          build_structured_payload_labkit(
            message: 'Duo Workflow concurrent session limit would be exceeded',
            Labkit::Fields::GL_USER_ID => @current_user.id,
            user_type: @current_user.user_type,
            Labkit::Fields::GL_ROOT_NAMESPACE_ID => @container.root_ancestor.id,
            workflow_environment: @params[:environment],
            active_session_count: active_count,
            max_concurrent_sessions: max,
            Labkit::Fields::DUO_WORKFLOW_DEFINITION => workflow_definition
          )
        )
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, user_id: @current_user.id, container_id: @container.id)
      end

      def log_goal_size
        goal = @params[:goal]
        return if goal.blank?

        Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'Duo Workflow goal size',
            goal_size: goal.to_s.size,
            Labkit::Fields::DUO_WORKFLOW_DEFINITION => workflow_definition
          )
        )
      end

      def resolve_source_pipeline(workflow)
        return unless @container.is_a?(::Project)

        flow = ::Ai::Catalog::FoundationalFlow[workflow_definition]
        flow&.resolve_source_pipeline_for(project: @container, goal: @params[:goal])
      rescue StandardError => err
        Gitlab::ErrorTracking.track_exception(err, workflow_id: workflow.id, container_id: @container.id)
        nil
      end

      # `execution_mode` is excluded so it can only come from the sealed classification.
      # `source`/`source_type` are excluded so the column is only set via #source_type_attributes.
      # The parent is excluded so it is only set via #parent_workflow_attributes, after the chain checks.
      # `flow_metadata_json` is excluded so only #started_flow_metadata sets it.
      def base_params
        params = @params.except(
          :issue_id, :merge_request_id, :resource, :service_account, :source, :source_type, :execution_mode,
          :parent_workflow, :parent_workflow_id, :flow_metadata_json
        )
        return params if explicit_catalog_item_version?

        params.except(:ai_catalog_item_version, :ai_catalog_item_version_id)
          .merge(ai_catalog_item_version_id: foundational_item_version&.id)
      end

      def source_type_attributes
        source_type = (@params[:source_type] || @params[:source]).to_s
        return {} unless Workflow.source_types.key?(source_type)

        { source_type: source_type }
      end

      def explicit_catalog_item_version?
        @params[:ai_catalog_item_version].present? || @params[:ai_catalog_item_version_id].present?
      end

      def foundational_item_version
        flow = ::Ai::Catalog::FoundationalFlow[workflow_definition]
        flow&.catalog_item&.latest_released_version_with_fallback
      end

      # `trigger_source` isn't a client-settable param anywhere (not declared in the REST
      # `workflow_params` block or any GraphQL mutation) - only trusted, server-side callers
      # (e.g. Ai::FlowTriggers::RunService, for system/scheduled/verification triggers) ever
      # set it, so it's safe to read straight off `@params`.
      def verification_run?
        @params[:trigger_source] == :verification
      end

      def service_account_attributes
        return {} unless @params[:service_account]

        { service_account: @params[:service_account] }
      end

      def create_workflow_system_note(workflow)
        noteable = workflow.noteable
        return unless noteable
        return if workflow.suppress_agent_session_note?

        # Who/what initiated the workflow
        # currently the user, but could be another agent
        # in future iterations
        trigger_source = @current_user
        note_author = workflow.service_account

        SystemNoteService.agent_session_started(
          noteable,
          noteable.project,
          workflow.id,
          trigger_source,
          note_author
        )
      rescue StandardError => err
        # `noteable` is nil when `workflow.noteable` itself raised
        Gitlab::ErrorTracking.track_exception(
          err,
          workflow_id: workflow.id,
          noteable_type: noteable&.class&.name,
          noteable_id: noteable&.id
        )
      end

      def post_create_error(workflow)
        enforce_precondition_check(workflow) || run_on_session_created(workflow)
      end

      def run_on_session_created(workflow)
        # A client-executed session runs locally, and its caller is not authorized as a catalog consumer.
        return if client_executed?

        flow = workflow.foundational_flow
        return unless flow&.on_session_created

        resource = @params[:resource] || workflow.resource
        return unless resource

        flow.run_on_session_created(resource: resource)
        nil
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)

        reason = :could_not_prepare_session
        summary = ::Ai::FoundationalFlowMessages.could_not_prepare_session_error
        drop_unready_workflow(workflow, summary, reason)

        error(summary, :unprocessable_entity, pass_back: { reason: reason })
      end

      # Fail a CI-backed flow at creation when the project cannot run it, rather than queuing a
      # DAP-tagged job that no runner will pick up. Drops the session through UpdateWorkflowStatusService
      # (real summary + failure note) and returns an error to the caller.
      def enforce_precondition_check(workflow)
        project = workflow.project
        return unless project
        return unless Feature.enabled?(:duo_workflow_precondition_check, project)
        # Client-executed sessions (IDE, CLI, and create-without-start) run locally and submit
        # no DAP-tagged CI job, so the runner check does not apply.
        return if client_executed?
        return if chat?

        # Only the readiness determination fails open: a probe error must not block session
        # creation (the current behaviour). Once a reason is known the session is always stopped.
        reason, summary =
          begin
            precondition_failure(project)
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
            nil
          end
        return unless reason

        # Drop the session, but still return the 422 even if the drop fails; a session left stuck
        # in `created` is reaped out of band by CleanStuckWorkflowsService.
        drop_unready_workflow(workflow, summary, reason)

        error(summary, :unprocessable_entity, pass_back: { reason: reason })
      end

      # Runner availability first: compute-minute exhaustion only strips instance runners, so a
      # project with a usable top-level group runner with the DAP workload tag can still run the job. Only
      # when no runner is available do we use the minutes check to choose the right message.
      def precondition_failure(project)
        return if ::Ai::DuoWorkflow::ProjectReadiness.new(project, @current_user).runner_available?

        if project.ci_minutes_usage.minutes_used_up?
          [:namespace_ci_minutes_used_up, ::Ai::FoundationalFlowMessages.namespace_ci_minutes_used_up_error]
        else
          tag = ::Ai::DuoWorkflows::Workflow.workload_tag_for(project)
          [:no_eligible_runner, ::Ai::FoundationalFlowMessages.no_eligible_runner_error(tag: tag)]
        end
      end

      def drop_unready_workflow(workflow, summary, reason)
        result = ::Ai::DuoWorkflows::UpdateWorkflowStatusService.new(
          workflow: workflow,
          status_event: 'drop',
          current_user: @current_user,
          summary: summary,
          drop_reason: UNREADY_DROP_REASONS.fetch(reason)
        ).execute
        return unless result.error?

        # The drop returns an error (not raises) if the transition or permission check fails, which
        # would leave the session stuck in `created` until the reaper cleans it up. Surface it.
        Gitlab::ErrorTracking.track_exception(
          CouldNotDropWorkflowError.new(result.message.to_s),
          workflow_id: workflow.id,
          reason: reason
        )
      rescue StandardError => e
        # A raised drop must not stop the caller from getting the 422 either; the stuck session is
        # reaped out of band. Track it here instead of letting it reach the fail-open probe rescue.
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id, reason: reason)
      end

      # A blocked foundational flow (see FoundationalFlow#blocked_for?) is not available, even when the
      # namespace enabled it: the block takes precedence over the namespace setting.
      def check_flow_blocked
        flow = ::Ai::Catalog::FoundationalFlow[workflow_definition]
        return unless flow&.blocked_for?(@container.root_ancestor)

        error('This flow is not available', :forbidden, pass_back: { reason: :flow_disabled_by_feature_flag })
      end

      def check_ai_catalog_item_access
        return unless @params[:ai_catalog_item_version]

        finder_params = {
          item_id: @params[:ai_catalog_item_version].ai_catalog_item_id
        }

        if @container.is_a?(::Project)
          finder_params[:project_id] = @container.id
        elsif @container.is_a?(::Namespace)
          finder_params[:group_id] = @container.id
        end

        return if Ai::Catalog::ItemConsumersFinder.new(@current_user, params: finder_params).execute.exists?

        error('ItemVersion not found', :not_found)
      end

      def check_access
        # Must stay above the client_executed? return: the authorizer classifies chat as CLIENT
        # without checking access.
        return check_agentic_chat_access if chat?

        # A client-executed classification is only ever minted by FlowExecutionAuthorizer,
        # which already authorized the run; re-checking here would refuse a valid seat used
        # outside its own namespace. https://gitlab.com/gitlab-org/gitlab/-/issues/623975
        return if client_executed?

        check_duo_workflow_access
      end

      def check_agentic_chat_access
        unless Ability.allowed?(@current_user, :access_duo_agentic_chat, @container)
          return error('forbidden to access agentic chat', :forbidden)
        end

        reference = FoundationalChatAgent.reference_from_workflow_definition(workflow_definition)

        agent = FoundationalChatAgent.with_workflow_definition(workflow_definition)
        if agent && !agent.licensed_for?(@container.root_ancestor)
          return error('agent requires Ultimate plan', :forbidden)
        end

        return if foundational_agents_settings_container&.foundational_agent_enabled?(reference)

        error('foundation agent disabled for namespace', :forbidden)
      end

      def check_duo_workflow_access
        return if Ability.allowed?(@current_user, :create_duo_workflow_for_ci, @container)

        error('forbidden to access duo workflow', :forbidden, pass_back: { reason: :cannot_create_workflow_pipeline })
      end

      def client_executed?
        !!classification&.client_executed?
      end

      # The only writer of `execution_mode`: later resolution sites hold a workflow but no
      # classification, so it has to be recorded here to reach them.
      def execution_mode_attributes
        return {} unless classification

        { execution_mode: client_executed? ? :client : :background }
      end

      def classification
        return unless @execution.is_a?(FlowExecutionAuthorizer::Classification)

        @execution
      end

      def workflow_definition
        @params['workflow_definition'] || @params[:workflow_definition]
      end

      def chat?
        FoundationalChatAgent.foundational_workflow_definition?(workflow_definition)
      end

      def container_attributes
        if @container.is_a?(::Project)
          { project: @container }
        elsif @container.is_a?(::Namespace)
          { namespace: @container }
        end
      end

      def noteable_attributes
        attributes = {}

        if @params[:issue_id].present?
          work_item = find_issue(@params[:issue_id])
          attributes[:issue_id] = work_item.id if work_item
        end

        if @params[:merge_request_id].present?
          mr = find_merge_request(@params[:merge_request_id])
          attributes[:merge_request_id] = mr.id if mr
        end

        # When no explicit noteable is provided, resolve from the foundational flow.
        # E.g. fix_pipeline derives merge_request from the pipeline URL (goal).
        # Also skip resolution when the API layer has already resolved AR objects
        # (e.g. agent_workflows passes :issue or :merge_request directly).
        resolve_noteable_from_flow(attributes) unless explicit_noteable?(attributes)

        attributes
      end

      def explicit_noteable?(attributes)
        attributes.any? || @params[:issue].present? || @params[:merge_request].present?
      end

      def resolve_noteable_from_flow(attributes)
        return unless @container.is_a?(::Project)

        flow = ::Ai::Catalog::FoundationalFlow[workflow_definition]
        noteable = flow&.resolve_noteable_for(project: @container, goal: @params[:goal])

        attributes[:merge_request_id] = noteable.id if noteable.is_a?(::MergeRequest)
        attributes[:issue_id] = noteable.id if noteable.is_a?(::Issue)
      end

      def find_issue(issue_iid)
        return unless @container.is_a?(::Project)

        IssuesFinder.new(@current_user, project_id: @container.id, iids: [issue_iid]).execute.first
      rescue StandardError => err
        Gitlab::ErrorTracking.track_exception(err, issue_iid: issue_iid, container_id: @container.id)
        nil
      end

      def find_merge_request(mr_iid)
        MergeRequestsFinder.new(@current_user, project_id: @container.id, iids: [mr_iid]).execute.first
      rescue StandardError => err
        Gitlab::ErrorTracking.track_exception(err, merge_request_iid: mr_iid, project_id: @container.id)
        nil
      end

      def enriched_error_message(response)
        case response.reason
        when :namespace_missing
          ::Ai::FoundationalFlowMessages.namespace_missing_error(@current_user)
        when :usage_billing_forbidden
          ::Ai::FoundationalFlowMessages.usage_billing_forbidden_error
        else
          response.message
        end
      end

      def http_status_for_quota_error(reason)
        case reason
        when :user_missing, :namespace_missing
          :bad_request
        when :usage_quota_exceeded
          :payment_required
        when :usage_billing_forbidden
          :forbidden
        else
          :internal_server_error
        end
      end

      def foundational_agents_settings_container
        @current_user.duo_foundational_agents_container(@container.root_ancestor)
      end

      def resolve_agent_privileges
        return unless @container
        return unless valid_container_for_governance?

        if @params[:agent_privileges]
          return clamp_client_privileges if @privileges_from_client

          # App-set privileges keep their previous behaviour. Returning rather than
          # falling through matters: server resolution would overwrite them.
          return if web_surface?
          return unless Feature.enabled?(:duo_workflow_local_tool_governance, @container.root_ancestor)

          return clamp_client_privileges
        end

        # Not governed, so keep platform defaults.
        if ::Ai::ToolRules::GovernanceSurface.ungoverned?(resolved_surface)
          @params[:agent_privileges] = ::Ai::DuoWorkflows::Workflow::AgentPrivileges::DEFAULT_PRIVILEGES
          return
        end

        result = execute_governance_resolution_with_retry

        if result&.success?
          @params[:agent_privileges] = result.payload[:agent_privileges]
          @params[:pre_approved_agent_privileges] = result.payload[:pre_approved_agent_privileges]
        else
          Gitlab::AppLogger.error(
            message: governance_failure_message('failing closed with no tools', result),
            container_id: @container.id,
            container_type: @container.class.name
          )
          @params[:agent_privileges] = []
          @params[:pre_approved_agent_privileges] = []
        end
      end

      # Callers cannot be trusted to self-report privileges, so intersect them with the
      # governance resolution. The surface only selects which rule column is read.
      def clamp_client_privileges
        return unless known_privileges?(@params[:agent_privileges], @params[:pre_approved_agent_privileges])
        # Load-bearing now the flag check is gone: an ungoverned session must not clamp to web rules.
        return if ::Ai::ToolRules::GovernanceSurface.ungoverned?(resolved_surface)

        result = execute_governance_resolution_with_retry(surface: clamp_surface)

        if result&.success?
          @params[:agent_privileges] &= result.payload[:agent_privileges]

          # Always set pre-approved privileges: leaving them unset would let the
          # DB column default apply unclamped. When adopting the resolved list,
          # constrain it to the clamped grants (a model invariant).
          @params[:pre_approved_agent_privileges] =
            if @params[:pre_approved_agent_privileges]
              @params[:pre_approved_agent_privileges] & result.payload[:pre_approved_agent_privileges]
            else
              result.payload[:pre_approved_agent_privileges] & @params[:agent_privileges]
            end
        else
          Gitlab::AppLogger.error(
            message: governance_failure_message('failing closed with no privileges', result),
            container_id: @container.id,
            container_type: @container.class.name
          )
          @params[:agent_privileges] = []
          @params[:pre_approved_agent_privileges] = []
        end
      end

      def pre_create_check
        check_flow_blocked || check_ai_catalog_item_access || check_access || check_caller_context ||
          check_denied_privilege_groups || check_bl_security_scan_limit
      end

      # Ops can tune the limit without a code change; 0 or less disables it.
      def max_active_bl_security_scans
        default = DEFAULT_MAX_ACTIVE_BL_SECURITY_SCANS_PER_ROOT_NAMESPACE
        value = ENV.fetch('DUO_WORKFLOW_MAX_CONCURRENT_BL_SECURITY_SCANS_PER_GROUP', default.to_s)

        # Base 10 so a leading zero is not read as octal (`010` is 10, not 8).
        Integer(value, 10, exception: false) || default
      end

      # Soft cap: two creates racing at the limit can both pass. Stuck sessions are dropped
      # by CleanStuckWorkflowsService, so they cannot hold a slot for long.
      def check_bl_security_scan_limit
        return unless workflow_definition == ::Ai::Catalog::FoundationalFlow::BL_SECURITY_FLOW_REFERENCE

        limit = max_active_bl_security_scans
        return if limit <= 0

        active_count = ::Ai::DuoWorkflows::Workflow
          .in_namespace_hierarchy(@container.root_ancestor)
          .with_workflow_definition(workflow_definition)
          .in_status_group(:active)
          .updated_after(BL_SECURITY_SCAN_ACTIVITY_WINDOW.ago)
          .limit(limit)
          .count
        return if active_count < limit

        Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'Business logic security scan refused: concurrent scan limit reached',
            Labkit::Fields::GL_ROOT_NAMESPACE_ID => @container.root_ancestor.id,
            max_concurrent_sessions: limit
          )
        )

        error("This group already has #{limit} business logic security scans running. " \
          "Try again when one of them finishes.", :too_many_requests,
          pass_back: { reason: :concurrent_scan_limit })
      end

      def check_denied_privilege_groups
        return unless resolved_surface == ::Ai::ToolRules::GovernanceSurface::BACKGROUND
        return unless Feature.enabled?(:duo_workflow_block_start_on_denied_group, @container.root_ancestor)

        required_privileges = ::Ai::Catalog::FoundationalFlow[workflow_definition].required_agent_privileges
        return if required_privileges.blank?

        result = execute_governance_resolution_with_retry

        unless result.success?
          Gitlab::AppLogger.error(
            message: governance_failure_message('refusing to start the flow', result),
            container_id: @container.id,
            container_type: @container.class.name
          )
          return error('Tool governance could not be resolved', :service_unavailable,
            pass_back: { reason: :governance_resolution_failed })
        end

        denied = required_privileges - result.payload[:agent_privileges]
        return if denied.empty?

        labels = denied.map { |privilege| denied_privilege_label(privilege) }

        error("An administrator denied the tools this flow needs to run: #{labels.to_sentence}.",
          :forbidden, pass_back: { reason: :privilege_groups_denied })
      end

      def denied_privilege_label(privilege)
        group = ::Ai::ToolRules::ResolutionService::PRIVILEGE_GROUP_TO_CONSTANT.key(privilege)
        tool_names = ::Ai::ToolRules::Registry.governed_tool_names_for(group_name: group)

        if tool_names.any? && tool_names.size <= MAX_DENIED_TOOLS_NAMED
          tool_names.to_sentence
        else
          "all tools in #{::Ai::DuoWorkflows::Workflow::AgentPrivileges::ALL_PRIVILEGES[privilege][:name]}"
        end
      end

      def web_surface?
        surface = @params[:environment].presence || :web

        ::Ai::ToolRule::WEB_SURFACES.include?(surface.to_s)
      end

      # `defined?`, not `||=`: nil is the common web result and must be cached too,
      # or background_surface repeats its query.
      def resolved_surface
        return @resolved_surface if defined?(@resolved_surface)

        @resolved_surface = ::Ai::ToolRules::GovernanceSurface.for(
          environment: @params[:environment],
          container: @container,
          workflow_definition: workflow_definition
        )
      end

      # Unrecognized environments (notably `external`) clamp against web rules, unlike
      # degraded_surface which sends them to local_access. Pre-existing, see
      # https://gitlab.com/gitlab-org/gitlab/-/issues/624032
      def clamp_surface
        resolved_surface || :web
      end

      def execute_governance_resolution_with_retry(surface: nil)
        surface ||= resolved_surface || degraded_surface
        @governance_resolutions ||= {}

        @governance_resolutions.fetch(surface.to_sym) do |key|
          @governance_resolutions[key] = resolve_governance_with_retry(
            build_resolution_service(surface: surface),
            container_id: @container.id,
            container_type: @container.class.name
          )
        end
      end

      def build_resolution_service(surface:)
        ::Ai::ToolRules::ResolutionService.new(
          namespace: @container.root_ancestor,
          surface: surface,
          project: @container.is_a?(::Project) ? @container : nil
        )
      end

      # Surface to use when background governance does not apply (flag off, or a
      # non-background environment). The environment passes through to its default
      # surface (ambient/web route to web_access), matching the pre-flag behaviour.
      def degraded_surface
        env = @params[:environment]&.to_s
        env.presence || 'web'
      end

      def valid_container_for_governance?
        @container.is_a?(::Project) || @container.is_a?(::Namespace)
      end
    end
  end
end
