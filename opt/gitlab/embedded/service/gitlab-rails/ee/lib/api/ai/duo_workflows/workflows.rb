# frozen_string_literal: true

module API
  module Ai
    module DuoWorkflows
      class Workflows < ::API::Base
        include PaginationParams
        include APIGuard
        include ::API::Concerns::McpAccess

        HEADERS_TO_FORWARD_AS_GRPC_METADATA = %w[
          X-Gitlab-Language-Server-Version
          X-Gitlab-Client-Type
          Langsmith-Trace
          X-Gitlab-Client-Name
          X-Gitlab-Client-Version
          X-Gitlab-Tracking-Context
        ].freeze

        TRACE_MAX_RESPONSE_BYTESIZE = 25.megabytes

        # Channels exposed to non-owner readers of a pipeline-triggered workflow.
        # Other channels (e.g. conversation_history, handover) carry raw tool
        # outputs that may include secrets or repository contents and are only
        # returned to the workflow owner.
        TRACE_SAFE_CHANNELS = %w[ui_chat_log plan status].freeze

        # Listed explicitly so new Workflow environments (for example `external`, which only
        # the external agent sessions API sets) don't become valid input to this endpoint.
        API_ENVIRONMENTS = %w[ide web chat_partial chat ambient].freeze

        FEATURE_SETTING_NAME_HEADER = ::Ai::DuoWorkflows::ServerSideExecutionService::FEATURE_SETTING_NAME_HEADER

        RESOLVE_DEPENDENCY_BUMP_WORKFLOW_DEFINITION =
          ::DependencyManagement::SecurityUpdate::TriggerResolveDependencyBumpWorkflowWorker::WORKFLOW_DEFINITION

        WORKFLOW_EVENTS = {
          ::Vulnerabilities::TriggerFalsePositiveDetectionWorkflowWorker::WORKFLOW_DEFINITION =>
            'trigger_sast_vulnerability_fp_detection_workflow',
          ::Vulnerabilities::TriggerResolutionWorkflowWorker::WORKFLOW_DEFINITION =>
            'trigger_sast_vulnerability_resolution_workflow',
          ::Vulnerabilities::TriggerSecretDetectionFalsePositiveDetectionWorkflowWorker::WORKFLOW_DEFINITION =>
            'trigger_secret_detection_vulnerability_fp_detection_workflow',
          RESOLVE_DEPENDENCY_BUMP_WORKFLOW_DEFINITION =>
            'trigger_resolve_dependency_bump_workflow'
        }.freeze

        helpers ::API::Helpers::DuoWorkflowHelpers
        helpers ::API::Helpers::AiUsersPerIpLimitHelpers
        helpers Gitlab::InternalEventsTracking

        feature_category :duo_agent_platform
        urgency :low

        allow_access_with_scope :ai_workflows, if: ->(request) do
          workflows_base = Gitlab::Utils.append_path(
            Gitlab.config.gitlab.relative_url_root, '/api/v4/ai/duo_workflows/workflows/')

          if request.get?
            ws_path = Gitlab::Utils.append_path(
              Gitlab.config.gitlab.relative_url_root, '/api/v4/ai/duo_workflows/ws')
            trace_path_pattern = %r{\A#{Regexp.escape(workflows_base)}\d+/trace\.jsonl\z}
            session_file_path_pattern = %r{\A#{Regexp.escape(workflows_base)}\d+/session_files/\d+\z}

            request.path == ws_path ||
              request.path.match?(trace_path_pattern) ||
              request.path.match?(session_file_path_pattern)
          elsif request.post?
            request.path.match?(%r{\A#{Regexp.escape(workflows_base)}\d+/execute\z})
          else
            false
          end
        end

        # The `send_duo_session_input` MCP tool re-dispatches the MCP request to the resume
        # endpoint, so the mcp scope must be accepted here. Only the request method is reliable
        # at that point (the path is still /api/v4/mcp), hence the method-based concern rather
        # than a path check. Narrowing this to declared MCP routes is tracked in
        # gitlab-org/security/gitlab#1751.
        allow_mcp_access_create

        before do
          authenticate!
        end

        helpers do
          # Prefers the most specific (subgroup) namespace from namespace_id/header,
          # falling back to root_namespace_id. Use this when checking cascading
          # settings that subgroups can override.
          def find_most_specific_namespace
            subgroup_id = params[:namespace_id].presence ||
              headers['X-Gitlab-Namespace-Id'].presence

            if subgroup_id
              ns = find_namespace(subgroup_id)

              if ns.nil?
                Gitlab::AppLogger.warn(
                  message: 'Namespace not found, falling back to root namespace',
                  namespace_id: subgroup_id
                )
              elsif !Ability.allowed?(current_user, :read_group, ns, composite_identity_check: false)
                Gitlab::AppLogger.warn(
                  message: 'User lacks permission on namespace, falling back to root namespace',
                  namespace_id: subgroup_id
                )
              else
                return ns
              end
            end

            find_request_namespace
          end

          def most_specific_namespace_or_root(root_namespace)
            find_most_specific_namespace || root_namespace
          end

          def find_root_namespace!
            namespace_id = request_namespace_id

            # First find the namespace (returns nil if not found)
            namespace = namespace_id && find_namespace(namespace_id)
            return current_user.governing_namespace unless namespace

            # Then enforce authorization (raises 404 if no access)
            not_found!('Namespace') unless Ability.allowed?(
              current_user, :read_group, namespace, composite_identity_check: false)

            root_namespace = namespace.root_ancestor

            # Validate namespace is contextually relevant to prevent
            # unauthorized access to model settings from unrelated namespaces
            validate_namespace_context!(root_namespace)

            root_namespace
          end

          def validate_namespace_context!(namespace)
            # If working in a project context, namespace must be the project's root namespace
            if params[:project_id].presence
              project = find_project!(params[:project_id])
              forbidden!("Namespace does not match project context") unless namespace.id == project.root_namespace.id
            end

            # If working in a namespace context (without project), must match or be ancestor
            return unless params[:namespace_id].presence

            context_namespace = find_namespace(params[:namespace_id])
            not_found!('Namespace') unless Ability.allowed?(
              current_user, :read_group, context_namespace, composite_identity_check: false)

            return if namespace.id == context_namespace.root_ancestor.id

            forbidden!("Namespace does not match workflow context")
          end

          def find_feature_setting_name
            # This header is sent only from the Node Executor.
            feature_setting_name_from_header =
              headers[FEATURE_SETTING_NAME_HEADER].presence

            # We treat agentic chat as the default feature for the /ws endpoint if
            # no header is present.
            (feature_setting_name_from_header ||
              ::Ai::ModelSelection::FeaturesConfigurable.agentic_chat_feature_name).to_sym
          end

          def find_user_selected_model_identifier
            # Currently, only the web agentic chat UI sends this attribute, as a query param.
            # The IDE does not yet send this attribute.
            params[:user_selected_model_identifier].presence
          end

          def find_workflow!(id)
            workflow = ::Ai::DuoWorkflows::Workflow.for_user_with_id!(current_user.id, id)
            return workflow if Ability.allowed?(current_user, :read_duo_workflow, workflow)

            forbidden_if_identity_verification_required!(workflow.resource_parent)
            forbidden!
          end

          def check_session_file_uploads_enabled!
            not_found! unless Feature.enabled?(:duo_workflow_session_file_persistent_uploads, current_user)
          end

          def find_session_file!(workflow_id, file_id)
            find_workflow!(workflow_id).session_files.find_by_id(file_id) || not_found!('Session file')
          end

          def create_session_file!(workflow, file)
            # Checked before assignment, which caches the file to disk under this name on local storage.
            if file.original_filename.bytesize > ::Ai::DuoWorkflows::SessionFile::MAX_FILENAME_LENGTH
              bad_request!('File name is too long')
            end

            ::Ai::DuoWorkflows::SessionFile.create!(
              workflow: workflow,
              file: file,
              size: file.size,
              # Workhorse does not forward the part's Content-Type, so derive it from the filename.
              content_type: ::Gitlab::Utils::MimeType.from_filename(file.original_filename)
            )
          rescue ActiveRecord::RecordInvalid => error
            bad_request!(error.message)
          end

          def get_current_organization_id
            Current.organization.id if Current.organization_assigned
          end

          def resume_catalog_workflow(workflow, container)
            consumer = find_catalog_consumer_for_workflow!(workflow)

            ::Ai::Catalog::Flows::ExecuteService.new(
              project: container,
              current_user: current_user,
              params: {
                item_consumer: consumer,
                execute_workflow: true,
                event_type: 'api_execution',
                user_prompt: workflow.goal,
                resume_context: {
                  existing_workflow: workflow,
                  human_approval: params[:human_approval],
                  human_message: params[:human_message]
                }
              }
            ).execute
          end

          def resume_foundational_workflow(workflow, container)
            decision = foundational_resume_decision(workflow)

            resume_params = {
              workflow_id: workflow.id,
              workflow_metadata: Gitlab::DuoWorkflow::Client.metadata(
                current_user, namespace: container.root_ancestor, project: container
              ).to_json
            }.merge(
              workflow_credential_params(
                container: container, service_account: workflow.service_account,
                workflow_definition: workflow.workflow_definition, workflow_id: workflow.id, workflow: workflow
              ),
              decision
            )

            ::Ai::DuoWorkflows::ResumeWorkflowService.new(workflow: workflow, params: resume_params).execute
          end

          # The executor takes human_message only with --approval false. A pending tool call or plan runs only when
          # the resume carries the decision.
          def foundational_resume_decision(workflow)
            return { human_approval: false, human_message: params[:human_message] } unless params[:human_approval]

            if workflow.awaiting_approval?
              refuse_message_with_approval!

              return { human_approval: true }
            end

            { goal: params[:human_message].presence || ::Ai::DuoWorkflows::RunEvent::APPROVED_REPLY }
          end

          # Only for the branch that bypasses ExecuteRunService, which refuses this itself.
          def refuse_message_with_approval!
            return if params[:human_message].blank?

            bad_request!(::Ai::DuoWorkflows::RunEvent::APPROVAL_WITH_MESSAGE_ERROR)
          end

          def resume_workhorse_workflow(workflow)
            event = workhorse_resume_event(workflow)
            claim = ::Ai::DuoWorkflows::TurnClaim.new(workflow.id)
            turn_already_running! unless claim.obtain

            begin
              # The previous turn releases the claim when it resumes, which can be after this request read the status.
              turn_already_running! unless status_on_primary(workflow) == workflow.status

              result = ::Ai::DuoWorkflows::ExecuteRunService.new(workflow, event: event, runtime: :workhorse).execute
            ensure
              claim.release unless result&.success?
            end
          end

          def turn_already_running!
            conflict!('This session is already running a turn. Wait for it to pause again.')
          end

          def status_on_primary(workflow)
            ::Gitlab::Database::LoadBalancing::SessionMap
              .current(::Ai::DuoWorkflows::Workflow.load_balancer)
              .use_primary { ::Ai::DuoWorkflows::Workflow.id_in(workflow.id).pick(:status) }
          end

          def workhorse_resume_event(workflow)
            ::Ai::DuoWorkflows::RunEvent.for_resume(
              workflow, approved: params[:human_approval], message: params[:human_message]
            )
          end

          def find_catalog_consumer_for_workflow!(workflow)
            catalog_item = workflow.ai_catalog_item_version&.item
            not_found!('AI Catalog item not found for this workflow') unless catalog_item

            consumer = ::Ai::Catalog::ItemConsumersFinder.new(current_user, params: {
              project_id: workflow.project.id,
              item_id: catalog_item.id
            }).execute.first

            not_found!('AI Catalog consumer not found for this workflow') unless consumer

            consumer
          end

          def gitlab_oauth_token(workflow_context_service = nil)
            workflow_context_service ||= workflow_context_generation_service

            # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/581556
            # It should be if find_feature_setting_name == FeaturesConfigurable.agentic_chat_feature_name
            oauth_token_result =
              if headers[FEATURE_SETTING_NAME_HEADER].present?
                workflow_context_service.generate_oauth_token_with_composite_identity_support
              else
                workflow_context_service.generate_oauth_token
              end

            if oauth_token_result.error?
              render_api_error!(oauth_token_result[:message], oauth_token_result[:http_status] || :forbidden)
            end

            oauth_token_result[:oauth_access_token]
          end

          # Mints before any workflow exists, so a resolved policy could only come from a namespace
          # the caller named. The service's container stays because it still picks the feature
          # setting and the governing-namespace claim; only governance resolution is suppressed.
          def duo_workflow_capabilities_and_expiry(workflow_context_service)
            result = workflow_context_service.generate_workflow_token(resolve_governance: false)
            bad_request!(result[:message]) if result.error?

            result.payload.slice(:capabilities, :expires_at)
          end

          def duo_workflow_list_tools(governing_namespace)
            feature_setting = ::Ai::FeatureSettingSelectionService.new(
              current_user,
              ::Ai::ModelSelection::FeaturesConfigurable.workflow_feature_name,
              governing_namespace
            ).execute.payload

            duo_workflow_list_tools_result = ::Ai::DuoWorkflow::DuoWorkflowService::Client.new(
              duo_workflow_service_url: Gitlab::DuoWorkflow::Client.url_for(
                feature_setting: feature_setting, user: current_user
              ),
              current_user: current_user,
              secure: Gitlab::DuoWorkflow::Client.secure?(feature_setting: feature_setting),
              feature_setting: feature_setting,
              container: governing_namespace
            ).list_tools
            bad_request!(duo_workflow_list_tools_result[:message]) if duo_workflow_list_tools_result[:status] == :error

            duo_workflow_list_tools_result
          end

          def build_messaging_callback_context(container)
            return if params[:callback_hook_id].blank?

            unless ::Gitlab::WebHooks::DuoFlowCallback.available?(container)
              bad_request!('callback_hook_id is not available for this namespace')
            end

            hook = ::Ai::DuoWorkflows::CallbackHooksFinder
              .new(container: container)
              .find_by_id(params[:callback_hook_id])

            unless hook
              bad_request!('callback_hook_id does not reference a webhook with Duo flow callbacks ' \
                'enabled in this project or its ancestor groups')
            end

            {
              'adapter' => ::Ai::Messaging::Adapters::Webhook.adapter_key,
              'hook_id' => hook.id,
              'client_reference' => params[:client_reference].presence
            }.compact
          end

          def create_workflow_params(container)
            wrkf_params = declared_params(include_missing: false).except(
              :start_workflow,
              :source_branch,
              :additional_context,
              :ai_catalog_item_consumer_id,
              :callback_hook_id,
              :client_reference
            )

            wrkf_params[:source_type] = :mcp if mcp_dispatched_request?
            wrkf_params.merge!(mcp_client_attributes)
            apply_flow_declared_privileges(wrkf_params)

            callback_context = build_messaging_callback_context(container)
            wrkf_params[:messaging_callback_context] = callback_context if callback_context

            if wrkf_params[:ai_catalog_item_version_id]
              wrkf_params[:ai_catalog_item_version] = ::Ai::Catalog::ItemVersion
                                                        .find(wrkf_params.delete(:ai_catalog_item_version_id))
            end

            if wrkf_params[:issue_id] && wrkf_params[:project_id]
              project = find_project!(wrkf_params[:project_id])
              wrkf_params[:issue] = project.issues.find_by_iid!(wrkf_params.delete(:issue_id))
            end

            if wrkf_params[:merge_request_id] && wrkf_params[:project_id]
              project = find_project!(wrkf_params[:project_id])
              wrkf_params[:merge_request] = project.merge_requests.find_by_iid!(wrkf_params.delete(:merge_request_id))
            end

            wrkf_params
          end

          def apply_flow_declared_privileges(wrkf_params)
            definition = privileges_declaring_definition(wrkf_params[:workflow_definition])
            ::Ai::DuoWorkflows::DeclaredPrivileges.apply!(wrkf_params, definition) if definition
          end

          def privileges_declaring_definition(workflow_definition)
            flow = ::Ai::Catalog::FoundationalFlow[workflow_definition]
            return flow if flow
            # Sessions in CI keep the defaults, so turning the flag off changes nothing.
            return unless workhorse_agent_session?(workflow_definition)

            ::Ai::FoundationalChatAgent.find_by_workflow_definition(workflow_definition)
          end

          # Fills in what the UI sends for a flow whose goal names a pipeline or merge request.
          def goal_resource_params(flow, container)
            return {} unless flow && container.is_a?(::Project) && params[:source_branch].blank?
            return pipeline_goal_params(flow, container) if flow.source_pipeline_resolver
            return merge_request_goal_params(flow, container) if flow.noteable_resolver

            {}
          end

          def pipeline_goal_params(flow, project)
            pipeline = flow.resolve_source_pipeline_for(project: project, goal: params[:goal])
            pipeline = nil unless pipeline && Ability.allowed?(current_user, :read_pipeline, pipeline)

            unless pipeline
              # REST callers keep the contract they had: the session starts without the context.
              if mcp_dispatched_request?
                bad_request!("#{flow.foundational_flow_reference} fixes a pipeline, so the goal must be " \
                  "the URL of a pipeline in #{project.full_path}")
              end

              return {}
            end

            merge_request = pipeline.all_merge_requests_by_recency.opened.first
            merge_request = nil unless merge_request &&
              Ability.allowed?(current_user, :read_merge_request, merge_request)

            envelopes = ::Ai::DuoWorkflows::AdditionalContext::PipelineContextBuilder
              .build(pipeline, merge_request: merge_request)

            { source_branch: pipeline.source_ref, additional_context: with_missing_categories(envelopes) }
          end

          def merge_request_goal_params(flow, project)
            merge_request = flow.resolve_noteable_for(project: project, goal: params[:goal])
            return {} unless merge_request.is_a?(::MergeRequest)
            return {} unless Ability.allowed?(current_user, :read_merge_request, merge_request)

            { source_branch: merge_request.source_branch }
          end

          def with_missing_categories(envelopes)
            sent = Array(params[:additional_context])
            sent_categories = sent.map { |envelope| envelope['Category'] || envelope[:Category] }

            sent + envelopes.reject { |envelope| sent_categories.include?(envelope['Category']) }
          end

          def track_event(consumer: nil, workflow: nil)
            workflow_definition = resolve_workflow_definition(consumer)
            return unless workflow_definition && WORKFLOW_EVENTS.key?(workflow_definition)

            if workflow_definition == RESOLVE_DEPENDENCY_BUMP_WORKFLOW_DEFINITION
              track_resolve_dependency_bump_event(workflow)
            else
              track_vulnerability_event(WORKFLOW_EVENTS[workflow_definition])
            end
          end

          def track_vulnerability_event(event_name)
            vulnerability = vulnerability_from_goal
            return unless vulnerability

            track_internal_event(
              event_name,
              project: vulnerability.project,
              additional_properties: {
                label: 'manual',
                value: vulnerability.id,
                property: vulnerability.severity
              }
            )
          end

          # Only use the project when the caller can read it and it's inside the namespace, so a foreign
          # or unreadable project_id can't sway governance.
          def request_project_within(namespace)
            project = find_project(params[:project_id].presence)
            return unless project && can?(current_user, :read_project, project)
            return unless namespace && project.root_ancestor.id == namespace.root_ancestor.id

            project
          end

          def track_resolve_dependency_bump_event(workflow)
            return unless workflow

            merge_request = workflow.merge_request

            track_internal_event(
              WORKFLOW_EVENTS[RESOLVE_DEPENDENCY_BUMP_WORKFLOW_DEFINITION],
              project: workflow.project,
              additional_properties: {
                label: 'manual',
                value: merge_request&.id,
                property: merge_request ? resolve_dependency_bump_iteration(merge_request).to_s : nil
              }.compact
            )
          end

          # Iteration = number of resolve_dependency_bump workflows that exist for
          # the MR, including the one just created. This mirrors the automatic
          # trigger, which reads the count before creating and adds one.
          def resolve_dependency_bump_iteration(merge_request)
            ::Ai::DuoWorkflows::Workflow
              .for_merge_request(merge_request)
              .with_workflow_definition(RESOLVE_DEPENDENCY_BUMP_WORKFLOW_DEFINITION)
              .count
          end

          def compute_server_capabilities(dws_capabilities:, namespace:)
            rails_capabilities = %w[
              job_trace_pagination tool_call_approval_source incremental_checkpoints incremental_checkpoints_only
              idle_status_event
            ]
            rails_capabilities << "advanced_search" if advanced_search_enabled?

            # Tool-read images: the client returns them only when the instance says it can carry them.
            rails_capabilities << "image_response" if Feature.enabled?(:dap_tool_image_input, current_user)

            # Filter DWS capabilities based on admin/namespace/project settings
            unless tool_approval_for_session_enabled?(namespace)
              dws_capabilities.delete('tool_call_approval')
              dws_capabilities.delete('tool_call_pattern_approval')
            end

            rails_capabilities << 'duo_auto_mode' if duo_auto_mode_enabled?(namespace)

            (rails_capabilities + dws_capabilities).uniq
          end

          def tool_approval_for_session_enabled?(namespace)
            ::Ai::DuoSettings::CascadingSettingResolver.enabled?(
              project: request_project_within(namespace),
              namespace: namespace,
              attribute: :tool_approval_for_session_enabled?
            )
          end

          def duo_auto_mode_enabled?(namespace)
            ::Ai::DuoSettings::AutoMode.consented?(container: request_project_within(namespace) || namespace)
          end

          def serialize_channel_entries(channel, value)
            if value.is_a?(Array)
              value.map do |item|
                entry = item.is_a?(Hash) ? item.merge('channel' => channel) : { 'channel' => channel, 'value' => item }
                "#{Gitlab::Json.dump(entry)}\n"
              end
            elsif value.is_a?(Hash) && value.values.any? { |v| v.is_a?(Array) && v.any? }
              value.flat_map do |sub_key, sub_value|
                serialize_channel_entries("#{channel}.#{sub_key}", sub_value)
              end
            else
              ["#{Gitlab::Json.dump({ 'channel' => channel, 'value' => value })}\n"]
            end
          end

          # The full p_duo_workflows_checkpoints table is being retired
          # (gitlab-org/gitlab#605653); when the read gate is open, source the trace's
          # channel_values from the slim header + incremental blobs so this path
          # stops reading that table.
          def trace_channel_values(workflow, thread, read, channels:)
            return blob_trace_channel_values(workflow, thread, channels: channels) if use_blob_read?(workflow, read)

            # The legacy path reads the compacted latest checkpoint row, which
            # cannot span threads, so the thread filter has nothing to act on.
            # rubocop:disable Gitlab/Ai/AvoidDirectCheckpointTableRead -- legacy branch, removed in https://gitlab.com/gitlab-org/gitlab/-/work_items/611971
            latest = workflow.checkpoints.latest
            # rubocop:enable Gitlab/Ai/AvoidDirectCheckpointTableRead
            latest&.checkpoint&.dig('channel_values') || {}
          end

          # `read` is an undeclared internal override that forces the read path
          # past the read gate. 'incremental' reads the header and blobs; 'legacy'
          # reads the checkpoints table; any other value (including nil) falls
          # through to the default read gate. 'incremental' still requires
          # incremental_checkpoints_enabled: a workflow that never wrote blobs has
          # nothing to reconstruct, so it falls back to the legacy path instead of
          # returning an empty trace.
          def use_blob_read?(workflow, read)
            case read
            when 'incremental' then workflow.incremental_checkpoints_enabled?
            when 'legacy' then false
            else workflow.incremental_blob_gate.read?
            end
          end

          # `thread`: absent -> full cross-thread trace (default); `latest` -> the
          # latest thread only; an integer -> that current_thread group only. A
          # value with no matching group (non-numeric, or numeric but out of the
          # current_thread column's int4 range) returns an empty trace instead of
          # querying, since the query itself would raise on an out-of-range integer.
          def blob_trace_channel_values(workflow, thread, channels:)
            case thread
            when nil, ''
              workflow.full_trace_channel_values(channels: channels)
            when 'latest'
              header = workflow.latest_checkpoint_header
              header ? workflow.reconstructed_channel_values(header, channels: channels) : {}
            else
              return {} unless thread.match?(/\A\d+\z/) && thread.to_i <= ::Gitlab::Database::MAX_INT_VALUE

              # Scoped to the top-level lineage, like #latest_checkpoint_header: a
              # nested subagent's header can share a current_thread id with the
              # workflow's own group, and only the workflow's own group is meant here.
              header = workflow.checkpoint_headers.for_checkpoint_ns(nil).for_current_thread(thread.to_i).last
              header ? workflow.reconstructed_channel_values(header, channels: channels) : {}
            end
          end

          def advanced_search_enabled?
            # advanced_search is a capability flag, not governance, so it uses the project directly.
            project = find_project(params[:project_id].presence)
            namespace_id = params[:root_namespace_id].presence ||
              params[:namespace_id].presence ||
              headers['X-Gitlab-Namespace-Id'].presence
            namespace = find_namespace(namespace_id)

            ::Gitlab::CurrentSettings.search_using_elasticsearch?(scope: project || namespace)
          end

          def duo_cli_request?
            headers['X-Gitlab-Client-Name'] == 'Duo CLI'
          end

          def mcp_dispatched_request?
            request.path == Gitlab::Utils.append_path(
              Gitlab.config.gitlab.relative_url_root, '/api/v4/mcp')
          end

          # With chaining on, a flow's composite identity token must name its own workflow as the parent,
          # so the chain limits apply.
          def parent_workflow_for_flow_request!(container)
            return unless Feature.enabled?(:ai_flow_trigger_chaining, container.root_ancestor)
            return if ::Gitlab::Auth::Identity.resolve_composite_identity_actor(current_user) == current_user

            parent_workflow = ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow_for_request(current_user)
            return parent_workflow if parent_workflow

            forbidden!('An agent can only start a workflow from a workflow it is allowed to update')
          end

          def mcp_client_attributes
            return {} unless mcp_dispatched_request?

            client_info = request.env[::Gitlab::Mcp::ClientInfo::RACK_ENV_KEY]
            return {} unless client_info

            { source_client_name: client_info.name, source_client_version: client_info.version }.compact
          end

          def workhorse_agent_session?(workflow_definition)
            params[:start_workflow].present? &&
              mcp_dispatched_request? &&
              ::Ai::FoundationalChatAgent.mcp_workhorse_session?(workflow_definition, current_user)
          end

          # Authorized when the session was created, and again by the :execute endpoint the turn runs through.
          def start_workhorse_agent_session!(workflow)
            result = ::Ai::DuoWorkflows::ExecuteRunService.new(
              workflow, event: { type: 'input', text: workflow.goal.to_s }, runtime: :workhorse
            ).execute

            render_api_error!(result.message, :unprocessable_entity) if result.error?
          end

          def duo_cli_disabled_by_admin?
            !::Ai::Setting.for_organization_read_only(::Current.organization).duo_cli_enabled
          end

          def audit_duo_cli_session_blocked
            audit_context = {
              name: 'duo_cli_session_blocked',
              author: current_user,
              scope: current_user,
              target: current_user,
              message: 'Duo CLI session was blocked because the administrator disabled Duo CLI'
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end

          # Resolves the request context, then delegates payload assembly to
          # ConnectionConfigService. The workflow is passed in because the WebSocket
          # handshake and :execute resolve it differently, and so is the definition:
          # :ws has no workflow to read it from until the client sends StartWorkflowRequest.
          def duo_workflow_connection_config(
            workflow:, workflow_definition: params[:workflow_definition], trusted_job_caller: false,
            flow_identity: false)
            root_namespace = find_root_namespace!
            billing_namespace =
              if root_namespace && ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
                current_user.governing_namespace(root_namespace)
              else
                root_namespace
              end

            forbidden!("Missing default GitLab Duo namespace user preference") unless billing_namespace

            forbidden_if_identity_verification_required!(root_namespace)

            most_specific_namespace = most_specific_namespace_or_root(root_namespace)

            push_feature_flags(root_namespace, feature_setting_name: find_feature_setting_name)

            model_metadata_service = duo_agent_platform_model_metadata_service(root_namespace)

            forbidden_if_credit_gated_model_selected!(model_metadata_service, root_namespace)

            connection_config = ::Ai::DuoWorkflows::ConnectionConfigService.new(
              current_user,
              duo_workflow_gitlab_token(workflow_definition, workflow, flow_identity: flow_identity),
              root_namespace: root_namespace,
              billing_namespace: billing_namespace,
              namespace: most_specific_namespace,
              project: request_project_within(root_namespace),
              workflow: workflow,
              request_metadata: duo_workflow_request_metadata(workflow_definition, trusted_job_caller),
              # dws_capabilities is empty here because the pre-authorization endpoints do not
              # fetch a DWS token. DWS-advertised capabilities flow through the access path.
              # See https://gitlab.com/gitlab-org/gitlab/-/work_items/592850 for a longer-term fix.
              server_capabilities: compute_server_capabilities(
                dws_capabilities: [],
                namespace: most_specific_namespace
              )
            )
            connection_config.model_metadata_service = model_metadata_service

            connection_config.execute
          end

          def duo_agent_platform_model_metadata_service(root_namespace)
            ::Ai::DuoWorkflows::DuoAgentPlatformModelMetadataService.new(
              root_namespace: root_namespace,
              current_user: current_user,
              user_selected_model_identifier: find_user_selected_model_identifier,
              feature_name: find_feature_setting_name
            )
          end

          def forbidden_if_credit_gated_model_selected!(model_metadata_service, root_namespace)
            return if find_user_selected_model_identifier.blank?
            return unless model_metadata_service.user_selected_model_credit_gated?

            Gitlab::AppLogger.info(
              message: 'DuoAgentPlatform::CreditGatedModel',
              event: 'Blocked request: selected model requires purchased GitLab Credits',
              error_code: 'MODEL_REQUIRES_PAID_CREDITS',
              Labkit::Fields::GL_USER_ID => current_user.id,
              Labkit::Fields::GL_ROOT_NAMESPACE_ID => root_namespace.id,
              model_identifier: find_user_selected_model_identifier,
              feature_name: find_feature_setting_name
            )

            forbidden!('MODEL_REQUIRES_PAID_CREDITS: The selected model requires purchased GitLab Credits. ' \
              'Purchase credits or select a different model.')
          end

          def duo_workflow_request_metadata(workflow_definition, trusted_job_caller)
            ::Ai::DuoWorkflows::ConnectionConfigService::RequestMetadata.new(
              project_id: params[:project_id],
              namespace_id: params[:namespace_id],
              client_type: params[:client_type],
              organization_id: get_current_organization_id,
              feature_setting_name: find_feature_setting_name,
              user_selected_model_identifier: find_user_selected_model_identifier,
              workflow_definition: workflow_definition,
              environment: params[:environment],
              ai_catalog_item_version_id: params[:ai_catalog_item_version_id],
              forwarded_grpc_metadata: duo_workflow_forwarded_grpc_metadata,
              trusted_job_caller: trusted_job_caller
            )
          end

          def duo_workflow_forwarded_grpc_metadata
            HEADERS_TO_FORWARD_AS_GRPC_METADATA.each_with_object({}) do |header, forwarded|
              header_value = headers[header]

              forwarded[header.downcase] = header_value if header_value.present?
            end
          end

          # Reuses the caller's bearer when it is already scoped for AI workflows,
          # otherwise mints a token for the flow.
          def duo_workflow_gitlab_token(workflow_definition, workflow, flow_identity: false)
            return flow_identity_gitlab_token(workflow) if flow_identity

            workflow_context_service = workflow_context_generation_service(
              workflow_definition: workflow_definition,
              workflow_id: workflow&.id
            )

            if workflow_context_service.already_scoped_for_ai_workflows?(access_token)
              parsed_oauth_token
            else
              gitlab_oauth_token(workflow_context_service).plaintext_token
            end
          end

          # The workflow's own state picks the identity, never a header the caller sends, and
          # there is no fallback service account.
          def flow_identity_gitlab_token(workflow)
            service_account = workflow.service_account if acts_as_flow_service_account?(workflow)
            container = workflow.project if service_account
            workflow_context_service = ::Ai::DuoWorkflows::WorkflowContextGenerationService.new(
              current_user: current_user,
              organization: container&.organization || ::Current.organization,
              workflow_definition: workflow.workflow_definition,
              service_account: service_account,
              container: container,
              surface: ::Ai::ToolRules::GovernanceSurface.from_environment(
                workflow.environment,
                container: workflow.resource_parent,
                workflow_definition: workflow.workflow_definition
              ),
              trigger_source: workflow.trigger_source,
              workflow_id: workflow.id
            )
            return parsed_oauth_token if workflow_context_service.already_scoped_for_ai_workflows?(access_token)

            oauth_token_result =
              if service_account
                workflow_context_service.generate_oauth_token_with_composite_identity_support
              else
                workflow_context_service.generate_oauth_token
              end

            if oauth_token_result.error?
              render_api_error!(oauth_token_result[:message], oauth_token_result[:http_status] || :forbidden)
            end

            oauth_token_result[:oauth_access_token].plaintext_token
          end

          # A flow that runs on Workhorse acts as its own service account, as its CI run would, but only
          # where a CI run could start: in a project that allows flow execution.
          def acts_as_flow_service_account?(workflow)
            workflow.last_runtime == :workhorse && can?(current_user, :execute_duo_workflow_in_ci, workflow)
          end

          # The request attributes duo_workflow_connection_config reads. The :ws
          # endpoint reads the same set but leaves it undeclared; declare it here so
          # the new endpoint gets Grape validation and API docs. workflow_definition and
          # environment are absent on purpose: both are read off the workflow record here.
          params :duo_workflow_connection_params do
            optional :project_id, type: String, limit: 255, desc: 'ID or path of the project to associate the flow ' \
                                                              'with.',
              documentation: { example: '1' }
            optional :namespace_id, type: String, limit: 255, desc: 'ID or path of the namespace to associate the ' \
                                                                'flow with.',
              documentation: { example: '1' }
            optional :root_namespace_id, type: String, limit: 255, desc: 'The ID of the root namespace',
              documentation: { example: '1' }
            optional :ai_catalog_item_version_id, type: Integer,
              desc: 'The ID of the AI Catalog ItemVersion that sourced the flow config used by the workflow.',
              documentation: { example: 1 }
            optional :client_type, type: String, limit: 255, desc: 'The type of client starting the session',
              documentation: { example: 'browser' }
            optional :user_selected_model_identifier, type: String, limit: 255,
              desc: 'Identifier of the model the user selected for this session',
              documentation: { example: 'claude_sonnet_4_5' }
          end

          params :workflow_params do
            optional :project_id, type: String, desc: 'ID or path of the project to associate the flow with.',
              documentation: { example: '1' }
            optional :namespace_id, type: String, desc: 'ID or path of the namespace to associate the flow with.',
              documentation: { example: '1' }
            optional :ai_catalog_item_consumer_id, type: Integer,
              desc: 'The ID of AI Catalog ItemConsumer that configures which catalog item to execute.',
              documentation: { example: 1 }
            optional :start_workflow, type: Boolean,
              desc: 'When true, starts the flow after creating it.',
              documentation: { example: true }
            optional :goal, type: String, desc: 'Description of the task for the agent to complete, for example `Fix ' \
                                            'the failing pipeline`.',
              documentation: { example: 'Fix pipeline for merge request 1 in project 1' }
            optional :agent_privileges, type: [Integer], desc: 'The actions the agent is allowed to perform',
              documentation: { example: [1] }
            optional :pre_approved_agent_privileges, type: [Integer],
              desc: 'Privilege IDs the agent can use without asking for user approval. Must be a subset of ' \
                '`agent_privileges`.',
              documentation: { example: [1] }
            optional :workflow_definition, type: String, desc: 'workflow type based on its capability',
              documentation: { example: 'software_developer' }
            optional :allow_agent_to_request_user, type: Boolean,
              desc: 'If `true`, the agent may pause to ask the user questions before proceeding. If `false`, the ' \
                'agent runs to completion without user input. Defaults to `true`.',
              documentation: { example: true }
            optional :image, type: String,
              desc: 'Container image to use for the flow. Applies only when the flow runs in a CI pipeline.',
              documentation: { example: 'registry.gitlab.com/gitlab-org/duo-workflow/custom-image:latest' }
            optional :source_branch, type: String,
              desc: 'Source branch for the flow. When not specified, a flow whose goal names a pipeline or ' \
                'merge request, such as fix_pipeline/v1, uses its branch, and other flows use the default ' \
                'branch. Applies only when the flow runs in a CI pipeline.',
              documentation: { example: 'main' }
            optional :environment, type: String,
              values: API_ENVIRONMENTS,
              desc: 'Execution environment for the workflow.',
              documentation: { example: 'web' }
            optional :ai_catalog_item_version_id, type: Integer,
              desc: 'ID of the AI Catalog item version that sourced the flow configuration used by the workflow.',
              documentation: { example: 1 }
            optional :additional_context, type: Array,
              desc: 'Additional context for the flow. Each element is an object with at least `Category` and ' \
                '`Content` keys. `Content` is a JSON-serialized string.',
              documentation: {
                example: '[{"Category": "agent_user_environment", "Content": "{\"merge_request_url\": ' \
                  '\"https://gitlab.com/project/-/merge_requests/1\"}", "Metadata": "{}"}]'
              } do
                requires :Category, type: String, desc: 'Category of the context detail.'
                requires :Content, type: String, desc: 'Content of the context detail.'
              end
            optional :issue_id, type: Integer,
              desc: 'Internal ID of the issue to associate the flow with. Requires `project_id`.',
              documentation: { example: 123 }
            optional :merge_request_id, type: Integer,
              desc: 'Internal ID of the merge request to associate the flow with. Requires `project_id`.',
              documentation: { example: 123 }
            optional :source, type: String, desc: 'Where the session was triggered from in the UI.',
              values: ::Ai::DuoWorkflows::Workflow::CLIENT_SOURCE_TYPES.keys.map(&:to_s),
              documentation: { example: 'merge_request_code_conflict' }
            optional :callback_hook_id, type: Integer,
              desc: 'ID of a webhook with GitLab Duo flow callbacks enabled. When provided, GitLab POSTs flow ' \
                'lifecycle events to that webhook so the client does not have to poll. The hook must belong ' \
                'to the project or namespace the flow runs in, or to one of its ancestor groups.',
              documentation: { example: 42, hidden: true }
            optional :client_reference, type: String, limit: 255,
              desc: 'An opaque string echoed back in every callback payload, ' \
                'useful for correlating callbacks to the triggering request.',
              documentation: { example: 'autoflow-run-abc123', hidden: true }
          end
        end

        namespace :ai do
          namespace :duo_workflows do
            resources :direct_access do
              desc 'Connection details for accessing Duo Agent Platform Service directly' do
                detail 'Returns connection details for direct access to the Duo Agent Platform Service.'
                tags ['gitlab_duo_workflows']
                success code: 201
                failure [
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' },
                  { code: 429, message: 'Too many requests' }
                ]
              end

              params do
                optional :workflow_definition, type: String, desc: 'workflow type based on its capability',
                  documentation: { example: 'software_developer' }
                optional :root_namespace_id, type: String, desc: 'ID of the root namespace.',
                  documentation: { example: '1' }
                optional :project_id, type: String, desc: 'ID or URL-encoded path of the project.',
                  documentation: { example: '1' }
              end

              route_setting :lifecycle, :experiment
              route_setting :authorization,
                permissions: :create_duo_workflow_direct_access_token,
                boundary_type: :user
              post do
                check_rate_limit!(:duo_workflow_direct_access, scope: { user: current_user })
                check_ai_users_per_ip_limit!

                root_namespace = find_root_namespace!

                forbidden_if_identity_verification_required!(root_namespace)
                forbidden_unless_usage_quota_available!(root_namespace)

                oauth_token = gitlab_oauth_token
                governed_project = request_project_within(root_namespace)
                billing_namespace = current_user.governing_namespace(governed_project || root_namespace)

                workflow_context_service = workflow_context_generation_service(
                  container: governed_project || root_namespace
                )
                mint = duo_workflow_capabilities_and_expiry(workflow_context_service)
                feature_setting = workflow_context_service.duo_agent_platform_feature_setting
                dws_capabilities = mint[:capabilities] || []

                access = {
                  gitlab_rails: {
                    base_url: Gitlab.config.gitlab.url,
                    token: oauth_token.plaintext_token,
                    token_expires_at: oauth_token.expires_at
                  },
                  duo_workflow_service: {
                    base_url: Gitlab::DuoWorkflow::Client.url_for(feature_setting: feature_setting, user: current_user),
                    # The token is withheld, but the expiry must stay populated: the language
                    # server takes the min of this and the Rails token expiry to schedule
                    # refresh, and throws AUTH_TOKEN_FETCH_ERROR on a blank value.
                    token: '',
                    token_expires_at: mint[:expires_at],
                    headers: Gitlab::AiGateway.public_headers(
                      user: current_user,
                      ai_feature_name: :duo_workflow,
                      unit_primitive_name: :duo_agent_platform,
                      organization_id: get_current_organization_id,
                      namespace_id: find_most_specific_namespace&.id,
                      project_id: governed_project&.id,
                      governing_namespace_id: billing_namespace&.id
                    ).transform_keys(&:downcase),
                    secure: Gitlab::DuoWorkflow::Client.secure?(feature_setting: feature_setting)
                  },
                  workflow_metadata: Gitlab::DuoWorkflow::Client.metadata(current_user,
                    namespace: find_request_namespace || root_namespace,
                    project: governed_project),
                  server_capabilities: compute_server_capabilities(
                    dws_capabilities: dws_capabilities,
                    namespace: most_specific_namespace_or_root(root_namespace)
                  )
                }

                present access, with: Grape::Presenters::Presenter
              end
            end

            resources :list_tools do
              desc 'List Duo Agent Platform tools' do
                detail 'Returns a list of all available Duo Agent Platform tools.'
                tags ['gitlab_duo_workflows']
                success code: 200
                failure [
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' },
                  { code: 429, message: 'Too many requests' }
                ]
              end

              params do
                optional :workflow_definition, type: String, desc: 'workflow type based on its capability',
                  documentation: { example: 'software_developer' }
              end

              route_setting :lifecycle, :experiment
              route_setting :authorization,
                permissions: :read_duo_workflow_tool,
                boundary_type: :user
              get do
                check_rate_limit!(:duo_workflow_direct_access, scope: { user: current_user })

                governing_namespace = current_user.governing_namespace
                if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && governing_namespace.nil?
                  message = if current_user.user_preference.duo_default_namespace_candidates.exists?
                              'Missing default GitLab Duo namespace user preference'
                            else
                              'No GitLab Duo namespace available'
                            end

                  forbidden!(message)
                end

                forbidden_if_identity_verification_required!(governing_namespace)

                result = duo_workflow_list_tools(governing_namespace)

                present(result.payload, with: Grape::Presenters::Presenter)
              end
            end

            desc 'Get Duo Workflows WebSocket connection details' do
              detail 'Retrieves WebSocket connection information to establish a session with Duo Workflows.'
              tags ['gitlab_duo_workflows']
              success code: 200
              failure [
                { code: 401, message: 'Unauthorized' },
                { code: 403, message: 'Forbidden' },
                { code: 404, message: 'Not found' },
                { code: 429, message: 'Too many requests' }
              ]
            end
            params do
              optional :workflow_id, type: String,
                desc: 'ID of the existing workflow. When provided and the workflow has a stored model selection, ' \
                  'that selection is reused to ensure provider stickiness.',
                documentation: { example: '1' }
              # Deliberately unrestricted: rejecting an unrecognised value would fail a request
              # that previously succeeded, and it already falls back to web.
              optional :environment, type: String, limit: 255,
                desc: 'Environment the session runs in. Used to resolve tool governance when ' \
                  'the client connects before sending workflow_id. Only `ide`, `chat`, and ' \
                  '`chat_partial` affect tool governance. Any other value falls back to `web`.',
                documentation: { example: 'ide' }
            end
            route_setting :lifecycle, :experiment
            route_setting :authorization,
              permissions: :read_duo_workflow_websocket,
              boundary_type: :user
            get :ws do
              require_gitlab_workhorse!

              status :ok
              content_type Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE

              check_ai_users_per_ip_limit!

              workflow = if params[:workflow_id].present?
                           ::Ai::DuoWorkflows::Workflow.for_user_with_id!(current_user.id, params[:workflow_id])
                         end

              # The workflow's own CI job connects with its service account's composite identity.
              trusted_job_caller = workflow&.service_account_id.present? &&
                service_account_from_composite_identity&.id == workflow.service_account_id

              config = duo_workflow_connection_config(workflow: workflow, trusted_job_caller: trusted_job_caller)
              # Workhorse checks the client's start request against this workflow.
              config = config.merge(WorkflowID: workflow.id.to_s) if workflow

              { DuoWorkflow: config }
            end

            namespace :workflows do
              namespace ':workflow_id' do
                desc 'Get workflow trace as JSONL' do
                  detail 'Returns the full trace of a workflow session as JSON Lines (JSONL). ' \
                    'Each line is a JSON object representing one checkpoint event in chronological order.'
                  tags ['gitlab_duo_workflows']
                  success code: 200
                  failure [
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                end
                params do
                  requires :workflow_id, type: Integer, desc: 'ID of the workflow.',
                    documentation: { example: 1 }
                  optional :full, type: Boolean,
                    desc: 'If `true`, includes internal channels such as conversation history and handover. ' \
                      'Restricted to the workflow owner. Non-owners receive a `403`.',
                    documentation: { example: false }
                  optional :thread, type: String,
                    desc: 'Thread to return. Omit for the full trace across all threads. Use `latest` for the most ' \
                      'recent thread, or a thread ID for a specific thread. Has no effect on workflows ' \
                      'that do not use incremental checkpoint storage.',
                    documentation: { example: 'latest' }
                  # `read` is an internal override read straight from params (see
                  # use_blob_read?). It is intentionally not declared here, so it
                  # stays out of the published API docs and no consumer depends on
                  # it before https://gitlab.com/gitlab-org/gitlab/-/work_items/611971 removes it.
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization,
                  permissions: :read_duo_workflow,
                  boundary_type: :user
                get 'trace.jsonl' do
                  full = params[:full].present?

                  workflow = if full
                               # for_user_with_id! scopes to current_user; a non-owner
                               # requesting full=true gets 404, mirroring the legacy behavior.
                               find_workflow!(params[:workflow_id])
                             else
                               found = ::Ai::DuoWorkflows::Workflow.find_by_id(params[:workflow_id])
                               not_found!('Workflow') unless found

                               # A 403 would confirm the session exists; other users'
                               # private sessions must be indistinguishable from unknown ids.
                               if found.private_messaging_session? && !found.invoked_by?(current_user)
                                 not_found!('Workflow')
                               end

                               forbidden_if_identity_verification_required!(found.resource_parent)

                               authorize!(:read_duo_workflow, found)

                               found
                             end

                  # A metadata-retention session keeps no internal channels to show.
                  forbidden!('Session keeps metadata only') if full && workflow.metadata_content_retention?

                  content_type 'application/x-ndjson'
                  env['api.format'] = :binary

                  lines = []

                  if workflow.goal.present?
                    lines << "#{Gitlab::Json.dump({ 'channel' => 'goal', 'value' => workflow.goal })}\n"
                  end

                  # channels: nil on the blob-read path fetches and decodes only the
                  # safe set up front for full: false, instead of loading every
                  # channel's full history and discarding the internal ones below.
                  channels = full ? nil : TRACE_SAFE_CHANNELS
                  channel_values = trace_channel_values(workflow, params[:thread], params[:read], channels: channels)
                  channel_values = channel_values.slice(*TRACE_SAFE_CHANNELS) unless full

                  if workflow.metadata_content_retention?
                    channel_values = ::Ai::DuoWorkflows::ContentRetention.channel_values(channel_values)
                  end

                  lines += channel_values.flat_map { |channel, value| serialize_channel_entries(channel, value) }

                  body = lines.join
                  if body.bytesize > TRACE_MAX_RESPONSE_BYTESIZE
                    file_too_large!('Workflow trace exceeds maximum allowed size')
                  end

                  body
                end
              end

              desc 'Create a flow' do
                detail 'Creates and starts a flow.'
                tags ['gitlab_duo_workflows']
                success code: 201
                failure [
                  { code: 400, message: 'Validation failed' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: '403 Forbidden' },
                  { code: 404, message: 'Not found' },
                  { code: 422, message: 'Unprocessable entity' },
                  { code: 429, message: 'Too many requests' }
                ]
              end
              params do
                use :workflow_params
              end
              route_setting :mcp, tool_name: :create_duo_workflow,
                params: ::Mcp::Tools::DuoWorkflows::StartDuoSessionService::ROUTE_PARAMS,
                annotations: { readOnlyHint: false, destructiveHint: false }, resource_name: 'project',
                aggregators: [::Mcp::Tools::DuoWorkflows::StartDuoSessionService]
              route_setting :authorization,
                permissions: :create_duo_workflow,
                boundary_type: :user
              post do
                if duo_cli_request? && duo_cli_disabled_by_admin?
                  audit_duo_cli_session_blocked
                  forbidden!('Duo CLI has been disabled by your administrator')
                end

                ::Gitlab::QueryLimiting.disable!(
                  'https://gitlab.com/gitlab-org/gitlab/-/issues/566195', new_threshold: 125
                )

                container = if params[:project_id]
                              find_project!(params[:project_id])
                            elsif params[:namespace_id]
                              find_workflow_namespace!(params[:namespace_id])
                            else
                              ::Ai::UserAuthorizer.for(current_user).default_duo_namespace
                            end

                if container.nil?
                  bad_request!('No default namespace found. Please provide project_id or namespace_id, ' \
                    'or configure a default Duo namespace.')
                end

                forbidden!('Access to the container is not allowed') unless container_access_allowed?(container)

                forbidden_if_identity_verification_required!(container)
                check_ai_users_per_ip_limit!

                parent_workflow = parent_workflow_for_flow_request!(container)

                if params[:ai_catalog_item_consumer_id]
                  unless container.is_a?(Project)
                    bad_request!('AI Catalog flows can only be executed in project context')
                  end

                  consumer = find_item_consumer!(params[:ai_catalog_item_consumer_id], container)

                  # Not resolve_workflow_definition: that is params-first, so a caller
                  # could bypass the guard by sending a different workflow_definition.
                  validate_flow_start_request!(
                    consumer.item.foundational_flow_reference, container, client_executed: false
                  )
                  goal_params = goal_resource_params(consumer.item.foundational_flow, container)
                  require_repository_for_flow!(container) if can_execute_catalog_item?(consumer, container)

                  service_account = if consumer.project.present?
                                      consumer.parent_item_consumer&.service_account
                                    else
                                      consumer.service_account
                                    end

                  service_account = enforce_start_workflow_service_account(
                    service_account, container, consumer: consumer
                  )

                  flow_params = {
                    item_consumer: consumer,
                    service_account: service_account,
                    execute_workflow: params[:start_workflow].present?,
                    event_type: 'api_execution',
                    user_prompt: params[:goal],
                    source_branch: goal_params.fetch(:source_branch, params[:source_branch]),
                    additional_context: goal_params.fetch(:additional_context, params[:additional_context]),
                    issue_id: params[:issue_id],
                    merge_request_id: params[:merge_request_id],
                    messaging_callback_context: build_messaging_callback_context(container),
                    # Server-derived MCP attribution wins over the client-reported `source`.
                    source_type: mcp_dispatched_request? ? :mcp : params[:source],
                    parent_workflow: parent_workflow,
                    workflow_attributes: mcp_client_attributes
                  }

                  result = ::Ai::Catalog::Flows::ExecuteService.new(
                    project: container,
                    current_user: current_user,
                    params: flow_params
                  ).execute

                  render_catalog_flow_error!(result)

                  workflow = result.payload[:workflow]
                  workload_id = result.payload[:workload_id]

                  link_vulnerability_to_user_triggered_workflow(workflow)

                  track_event(consumer: consumer, workflow: workflow)

                  present workflow, with: ::API::Entities::Ai::DuoWorkflows::Workflow,
                    workload: { id: workload_id, message: result.message }
                else
                  validate_flow_start_request!(
                    params[:workflow_definition], container, client_executed: !params[:start_workflow].present?
                  )
                  goal_params = goal_resource_params(
                    ::Ai::Catalog::FoundationalFlow.find_by_reference(params[:workflow_definition]), container
                  )

                  workflow_params = create_workflow_params(container)

                  execution = authorize_flow_execution!(
                    workflow_params, container,
                    caller_can_execute: true,
                    start_workflow: params[:start_workflow].present?,
                    item_consumer_id: params[:ai_catalog_item_consumer_id]
                  )

                  workhorse_session = workhorse_agent_session?(workflow_params[:workflow_definition])
                  require_repository_for_flow!(container) unless workhorse_session
                  acts_as_user = workhorse_session

                  unless acts_as_user
                    workflow_params[:service_account] = enforce_start_workflow_service_account(
                      workflow_params[:service_account], container
                    )
                  end

                  workflow_params[:parent_workflow] = parent_workflow if parent_workflow

                  service = ::Ai::DuoWorkflows::CreateWorkflowService.new(
                    container: container, current_user: current_user, params: workflow_params,
                    execution: execution, privileges_from_client: true)

                  result = service.execute

                  forbidden!(result.message) if result.error? && result.http_status == :forbidden
                  not_found!(result.message) if result.error? && result.http_status == :not_found
                  if result.error? && result.http_status == :payment_required
                    forbidden!(::API::Helpers::DuoWorkflowHelpers::INSUFFICIENT_CREDITS_MESSAGE)
                  end

                  if result.error? && result.http_status == :unprocessable_entity
                    render_api_error!(result[:message], :unprocessable_entity)
                  end

                  bad_request!(result[:message]) if result[:status] == :error

                  link_vulnerability_to_user_triggered_workflow(result[:workflow])

                  push_ai_gateway_headers(scope: container,
                    subject: workflow_params[:service_account] || current_user)

                  if workhorse_session
                    start_workhorse_agent_session!(result[:workflow])
                  elsif params[:start_workflow].present?
                    response = ::Ai::DuoWorkflows::StartWorkflowService.new(
                      workflow: result[:workflow],
                      params: start_workflow_params(result[:workflow].id, container: container,
                        service_account: workflow_params[:service_account],
                        workflow_definition: workflow_params[:workflow_definition]).merge(goal_params)
                    ).execute

                    if response.error?
                      status_code = case response.reason
                                    when :unprocessable_entity
                                      :unprocessable_entity
                                    when :feature_unavailable, :invalid_service_account
                                      :forbidden
                                    when :workload_failure, :repository_empty
                                      :unprocessable_entity
                                    else
                                      :internal_server_error
                                    end

                      if response.reason == :repository_empty
                        render_structured_api_error!(
                          { 'message' => response.message, 'reason' => 'repository_empty' },
                          status_code
                        )
                      else
                        render_api_error!(response.message, status_code)
                      end
                    else
                      workload_id = response.payload && response.payload[:workload_id]
                      message = response.message

                      track_event
                    end
                  end

                  workload = { id: workload_id, message: message } unless workhorse_session

                  present result[:workflow], with: ::API::Entities::Ai::DuoWorkflows::Workflow, workload: workload
                end
              end

              desc 'List all agent privileges' do
                detail 'Lists all available agent privileges with their IDs, names, descriptions, and whether each ' \
                  'is enabled by default. This endpoint has no supported attributes.'
                tags ['gitlab_duo_workflows']
                success code: 200
                failure [
                  { code: 401, message: 'Unauthorized' }
                ]
              end
              route_setting :authorization,
                permissions: :read_duo_workflow_agent_privilege,
                boundary_type: :user
              get 'agent_privileges' do
                present ::Ai::DuoWorkflows::Workflow::AgentPrivileges,
                  with: ::API::Entities::Ai::DuoWorkflows::Workflow::AgentPrivileges
              end

              params do
                requires :workflow_id, type: String, desc: 'ID of the workflow.'
              end
              namespace ':workflow_id' do
                desc 'Request Duo Workflows server-side execution connection details' do
                  detail 'Workhorse pre-authorization endpoint. Returns the connection details Workhorse ' \
                    'needs to run the flow itself over gRPC and stream the actions it receives back to the ' \
                    'caller, for callers that cannot execute actions of their own. Requests must arrive ' \
                    'through Workhorse.'
                  tags ['gitlab_duo_workflows']
                  success code: 200
                  failure [
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' },
                    { code: 429, message: 'Too many requests' }
                  ]
                end
                params do
                  requires :workflow_id, type: String, regexp: /\A\d+\z/,
                    desc: 'The ID of the workflow to execute',
                    documentation: { example: '1' }
                  use :duo_workflow_connection_params
                  optional :detached, type: Boolean,
                    desc: 'When true, asks Workhorse to answer once the run has started and keep it going ' \
                      'after the request ends.',
                    documentation: { example: true }
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization,
                  permissions: :read_duo_workflow_websocket,
                  boundary_type: :user
                post :execute do
                  require_gitlab_workhorse!

                  # Shares the limit with the other session bootstrap endpoints: every
                  # request here makes Workhorse hold a gRPC stream open for the whole run.
                  check_rate_limit!(:duo_workflow_direct_access, scope: { user: current_user })

                  check_ai_users_per_ip_limit!

                  workflow = find_workflow!(params[:workflow_id])

                  # Workhorse takes the workflow ID from here rather than from the caller's
                  # request body, which it does not authorize. The definition comes off the
                  # record for the same reason: it selects the MCP tool set and the minted
                  # token's feature, so the body must not be able to swap in another flow's.
                  config = duo_workflow_connection_config(
                    workflow: workflow,
                    workflow_definition: workflow.workflow_definition,
                    flow_identity: true
                  ).merge(WorkflowID: workflow.id.to_s)

                  # Workhorse reads only this field, never the query parameter, so the
                  # flag decides whether a caller asking for a detached run gets one.
                  if params[:detached] && Feature.enabled?(:duo_workflow_detached_server_side_execution, current_user)
                    config[:Detached] = true
                  end

                  status :ok
                  content_type Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE

                  { DuoWorkflow: config }
                end

                desc 'Workhorse authorize a session file upload' do
                  detail 'Workhorse pre-authorization endpoint for uploading a session file.'
                  tags ['gitlab_duo_workflows']
                  success code: 200
                  failure [
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization, skip_granular_token_authorization: :workhorse_pre_authorization
                post 'session_files/authorize' do
                  check_session_file_uploads_enabled!
                  authorize!(:update_duo_workflow, find_workflow!(params[:workflow_id]))

                  require_gitlab_workhorse!
                  status 200
                  content_type ::Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE

                  ::Ai::DuoWorkflows::SessionFileUploader.workhorse_authorize(
                    has_length: false,
                    maximum_size: ::Ai::DuoWorkflows::SessionFile::MAX_SIZE
                  )
                end

                desc 'Upload a session file' do
                  detail 'Uploads an image the user attached to the session.'
                  consumes ['multipart/form-data']
                  tags ['gitlab_duo_workflows']
                  success code: 201
                  failure [
                    { code: 400, message: 'Validation failed' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                end
                params do
                  requires :file, type: ::API::Validations::Types::WorkhorseFile, desc: 'The image file to upload',
                    documentation: { type: 'file' }
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization, permissions: :update_duo_workflow, boundary_type: :user
                post 'session_files' do
                  check_session_file_uploads_enabled!
                  require_gitlab_workhorse!

                  workflow = find_workflow!(params[:workflow_id])
                  authorize!(:update_duo_workflow, workflow)

                  session_file = create_session_file!(workflow, params[:file])

                  status :created
                  session_file.slice(:id, :workflow_id, :size, :content_type)
                    .merge(filename: session_file.file.filename)
                end

                desc 'Get a session file with its contents' do
                  detail 'Returns a file the user attached to the session, with its contents base64 encoded.'
                  tags ['gitlab_duo_workflows']
                  success code: 200
                  failure [
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                end
                params do
                  requires :file_id, type: Integer, desc: 'ID of the session file.', documentation: { example: 1 }
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization, permissions: :read_duo_workflow, boundary_type: :user
                # Base64 because the executor proxy returns the body in a proto3 string field.
                get 'session_files/:file_id' do
                  check_session_file_uploads_enabled!
                  session_file = find_session_file!(params[:workflow_id], params[:file_id])

                  session_file.slice(:id, :workflow_id, :size, :content_type)
                    .merge(filename: session_file.file.filename, data: Base64.strict_encode64(session_file.file.read))
                end

                desc 'Download a session file' do
                  detail 'Returns the raw contents of a file the user attached to the session.'
                  tags ['gitlab_duo_workflows']
                  success code: 200
                  failure [
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                end
                params do
                  requires :file_id, type: Integer, desc: 'ID of the session file.', documentation: { example: 1 }
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization, permissions: :read_duo_workflow, boundary_type: :user
                get 'session_files/:file_id/raw' do
                  check_session_file_uploads_enabled!
                  session_file = find_session_file!(params[:workflow_id], params[:file_id])

                  present_carrierwave_file!(
                    session_file.file, content_type: session_file.content_type, content_disposition: :attachment
                  )
                end

                desc 'Resume a paused workflow' do
                  detail 'Resumes execution of a previously paused workflow.'
                  tags ['gitlab_duo_workflows']
                  success code: 201
                  failure [
                    { code: 400, message: 'Validation failed' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' },
                    { code: 422, message: 'Unprocessable entity' },
                    { code: 429, message: 'Too many requests' }
                  ]
                end
                params do
                  requires :workflow_id, type: String, desc: 'ID of the workflow to resume.',
                    documentation: { example: '1' }
                  requires :human_approval, type: Boolean,
                    desc: 'If `true`, the human approves resuming the workflow.',
                    documentation: { example: true }
                  optional :human_message, type: String,
                    desc: 'Message accompanying the human decision.',
                    documentation: { example: 'Looks good, please proceed' },
                    limit: ::Mcp::Tools::DuoWorkflows::SendDuoSessionInputService::HUMAN_MESSAGE_MAX_LENGTH
                end
                # Exposed to MCP only through the `send_duo_session_input` aggregator, which owns the
                # model-facing description and input schema.
                route_setting :mcp, tool_name: :resume_duo_workflow,
                  params: [:workflow_id, :human_approval, :human_message],
                  annotations: { readOnlyHint: false, destructiveHint: false }, resource_name: 'workflow',
                  aggregators: [::Mcp::Tools::DuoWorkflows::SendDuoSessionInputService]
                route_setting :lifecycle, :experiment
                route_setting :authorization, permissions: :resume_duo_workflow, boundary_type: :user
                post :resume do
                  workflow = find_workflow!(params[:workflow_id])
                  authorize!(:resume_duo_workflow, workflow)
                  check_ai_users_per_ip_limit!

                  container = workflow.project || workflow.namespace

                  push_ai_gateway_headers(scope: container,
                    subject: workflow.service_account || current_user)

                  workhorse = workflow.mcp_workhorse_session?

                  result = if workhorse
                             resume_workhorse_workflow(workflow)
                           elsif workflow.chat?
                             resume_foundational_workflow(workflow, container)
                           else
                             resume_catalog_workflow(workflow, container)
                           end

                  bad_request!(result.message) if result.error?

                  workload = { id: result.payload[:workload_id], message: result.message } unless workhorse

                  present workflow, with: ::API::Entities::Ai::DuoWorkflows::Workflow, workload: workload
                end

                desc 'Restart a failed or stopped workflow as a new session' do
                  detail 'Creates and starts a new session with the flow, goal, noteable, source, privileges ' \
                    'and trigger of the given workflow. The original workflow is not modified.'
                  tags ['gitlab_duo_workflows']
                  success code: 201
                  failure [
                    { code: 400, message: 'Validation failed' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' },
                    { code: 409, message: 'Conflict' },
                    { code: 422, message: 'Unprocessable entity' },
                    { code: 429, message: 'Too many requests' }
                  ]
                end
                params do
                  requires :workflow_id, type: String, desc: 'The ID of the workflow to restart',
                    documentation: { example: '1' }
                end
                route_setting :lifecycle, :experiment
                route_setting :authorization, permissions: :restart_duo_workflow, boundary_type: :user
                post :restart do
                  workflow = find_workflow!(params[:workflow_id])
                  authorize!(:restart_duo_workflow, workflow)
                  forbidden_if_identity_verification_required!(workflow.project)
                  check_ai_users_per_ip_limit!

                  push_ai_gateway_headers(scope: workflow.project || workflow.namespace,
                    subject: workflow.service_account || current_user)
                  consumer = find_catalog_consumer_for_workflow!(workflow)

                  result = ::Ai::DuoWorkflows::RestartWorkflowService.new(
                    workflow: workflow,
                    current_user: current_user,
                    item_consumer: consumer,
                    service_account: consumer.active_service_account
                  ).execute

                  if result.error?
                    case result.reason
                    when :forbidden then forbidden!(result.message)
                    when :conflict then conflict!(result.message)
                    when :invalid_goal then bad_request!(goal_error_message(result, workflow.project))
                    else bad_request!(result.message)
                    end
                  end

                  present result.payload[:workflow], with: ::API::Entities::Ai::DuoWorkflows::Workflow,
                    workload: { id: result.payload[:workload_id], message: result.message }
                end
              end
            end
          end
        end
      end
    end
  end
end
