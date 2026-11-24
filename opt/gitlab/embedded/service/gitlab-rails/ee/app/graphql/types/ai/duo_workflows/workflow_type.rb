# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowType < Types::BaseObject
        graphql_name 'DuoWorkflow'
        description 'GitLab Duo Agent Platform session'
        implements Types::TodoableInterface
        present_using ::Ai::DuoWorkflows::WorkflowPresenter
        authorize :read_duo_workflow
        authorize_granular_token permissions: :read_duo_workflow, boundary: :user, boundary_type: :user

        FIELD_SCOPES = [:api, :read_api, :ai_features, :ai_workflows].freeze

        def self.authorization_scopes
          FIELD_SCOPES
        end

        field :id, type: GraphQL::Types::ID,
          scopes: FIELD_SCOPES,
          null: false, description: 'ID of the session.'

        # The user id will always be the current_user.id as
        # only workflow owners can read a workflow
        field :user_id, Types::GlobalIDType[User],
          scopes: FIELD_SCOPES,
          null: false, description: 'ID of the user.'

        field :user, ::Types::UserType,
          scopes: FIELD_SCOPES,
          null: true, description: 'User who created the session.'

        field :project_id, Types::GlobalIDType[Project],
          scopes: FIELD_SCOPES,
          null: true, description: 'ID of the project.'

        field :project, Types::ProjectType,
          scopes: FIELD_SCOPES,
          null: true, description: "Project that the session is in."

        field :namespace_id, Types::GlobalIDType[Namespace],
          scopes: FIELD_SCOPES,
          null: true, description: 'ID of the namespace.'

        field :namespace, Types::NamespaceType,
          scopes: FIELD_SCOPES,
          null: true, description: "namespace that the session is in."

        field :human_status, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: false, description: 'Human-readable status of the session.'

        field :created_at, Types::TimeType,
          scopes: FIELD_SCOPES,
          null: false, description: 'Timestamp of when the session was created.'

        field :updated_at, Types::TimeType,
          scopes: FIELD_SCOPES,
          null: false, description: 'Timestamp of when the session was last updated.'

        field :goal, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          description: 'Goal of the session.'

        field :workflow_definition, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          description: 'GitLab Duo Agent Platform flow type based on its capabilities.'

        field :environment, Types::Ai::DuoWorkflows::WorkflowEnvironmentEnum,
          scopes: FIELD_SCOPES,
          description: 'Environment, like IDE or web.'

        field :agent_privileges_names, [GraphQL::Types::String],
          scopes: FIELD_SCOPES,
          description: 'Privileges granted to the agent during execution.'

        field :pre_approved_agent_privileges_names, [GraphQL::Types::String],
          scopes: FIELD_SCOPES,
          description: 'Privileges pre-approved for the agent during execution.'

        # rubocop:disable Graphql/JSONType -- There is infinite number of possible keys representing tool names in this object
        field :tool_call_approvals, GraphQL::Types::JSON,
          scopes: FIELD_SCOPES,
          description: 'Tools approval per session policy.'
        # rubocop:enable Graphql/JSONType

        # Deliberately narrower than the type's token check (read_duo_workflow): any token that can read
        # the session may ask, and this only limits which user gets an answer.
        field :tool_access_policies,
          resolver: ::Resolvers::Ai::DuoWorkflows::ToolAccessPoliciesResolver,
          scopes: FIELD_SCOPES,
          authorize: :read_duo_workflow_tool_access_policy,
          description: 'Tool access policy the GitLab Duo Workflow Service enforces for the session ' \
            'when its token carries none. ' \
            'This field can only be resolved for one session in any single request.',
          experiment: { milestone: '19.6' } do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :tool_call_approved, GraphQL::Types::Boolean,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false,
          description: 'Whether the specified tool call is approved for the session.' do
          argument :tool_call_args, GraphQL::Types::String,
            required: true,
            description: 'JSON-serialized arguments for the tool call.',
            validates: { length: { maximum: 64.kilobytes } }
          argument :tool_name, GraphQL::Types::String,
            required: true,
            description: 'Name of the tool to check.'
        end

        field :tool_call_approval_match, Types::Ai::DuoWorkflows::ToolCallApprovalMatchType, # rubocop:disable GraphQL/ExtractType -- tool_call fields are integral to workflow
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false,
          description: 'Approval match details for the specified tool call.',
          experiment: { milestone: '19.3' } do
          argument :tool_call_args, GraphQL::Types::String,
            required: true,
            description: 'JSON-serialized arguments for the tool call.',
            validates: { length: { maximum: 64.kilobytes } }
          argument :tool_name, GraphQL::Types::String,
            required: true,
            description: 'Name of the tool to check.'
        end

        field :mcp_enabled, GraphQL::Types::Boolean,
          scopes: FIELD_SCOPES,
          description: 'Has MCP been enabled for the namespace.'

        field :incremental_checkpoints_enabled, GraphQL::Types::Boolean,
          scopes: FIELD_SCOPES,
          description: 'Indicates incremental checkpoints were enabled for the session at creation.'

        field :web_url, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'URL of the session.'

        field :web_path, GraphQL::Types::String, # rubocop:disable GraphQL/ExtractType -- Session URL and web search state are unrelated.
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Web path of the session.'

        field :web_search_enabled, GraphQL::Types::Boolean,
          scopes: FIELD_SCOPES,
          description: 'Whether web search is enabled for the session.',
          experiment: { milestone: '19.3' }

        field :allow_agent_to_request_user, GraphQL::Types::Boolean,
          scopes: FIELD_SCOPES,
          description: 'Allow the agent to request user input.'

        field :allow_client_injected_mcp_tools, GraphQL::Types::Boolean, # rubocop:disable GraphQL/ExtractType -- Requesting user input and MCP tool approval are unrelated.
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Indicates MCP tools supplied by the client skip the tool call approval gate. ' \
            'Toggled by the `dap_allow_client_injected_mcp_tools` feature flag; returns `false` when it is disabled.',
          experiment: { milestone: '19.5' }

        field :file_attachments_allowed, GraphQL::Types::Boolean,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Indicates file attachments are allowed for the session. ' \
            'Requires the `dap_web_chat_file_attachments` feature flag and, outside GitLab.com, ' \
            'the file attachments setting of the instance; returns `false` when either is disabled.',
          experiment: { milestone: '19.6' }

        field :web_search_allowed, GraphQL::Types::Boolean, # rubocop:disable GraphQL/ExtractType -- Instance or group permission, not the session toggle.
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Indicates web search is allowed for the session. On GitLab.com, the top-level group ' \
            'setting decides. On GitLab Self-Managed and GitLab Dedicated, the instance setting decides. ' \
            'Does not include the user choice in `webSearchEnabled`.',
          experiment: { milestone: '19.6' }

        field :status, Types::Ai::DuoWorkflows::WorkflowStatusEnum,
          scopes: FIELD_SCOPES,
          description: 'Status of the session.'

        field :status_name, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          description: 'Status name of the session.'

        field :status_group, Types::Ai::DuoWorkflows::WorkflowStatusGroupEnum, # rubocop: disable GraphQL/ExtractType -- does not make sense
          scopes: FIELD_SCOPES,
          description: 'Status group of the flow session.'

        # rubocop:disable GraphQL/ExtractType -- failure fields are intentionally kept flat for a consistent session-detail API
        field :failure_category, Types::Ai::DuoWorkflows::WorkflowFailureCategoryEnum,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Category of the failure. Null unless the session is failed.',
          experiment: { milestone: '19.6' }

        field :failure_cause, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Short user-facing cause of the failure. ' \
            'Null unless the session is failed, or when no clear cause is available.',
          experiment: { milestone: '19.6' }

        field :drop_reason, Types::Ai::DuoWorkflows::WorkflowDropReasonEnum,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Reason the session was failed. Null unless the session is failed.',
          experiment: { milestone: '19.6' }
        # rubocop:enable GraphQL/ExtractType

        field :first_checkpoint, Types::Ai::DuoWorkflows::WorkflowEventType,
          scopes: FIELD_SCOPES,
          description: "First checkpoint of the session." do
          argument :checkpoint_ns, GraphQL::Types::String,
            required: false,
            experiment: { milestone: '19.3' },
            description: 'LangGraph checkpoint namespace to scope the lookup to. ' \
              'Omit (or pass an empty string) for the session\'s own top-level checkpoint lineage; ' \
              'used internally to resolve one nested subgraph invocation, e.g. a delegated subagent.'
        end

        field :latest_checkpoint, Types::Ai::DuoWorkflows::WorkflowEventType,
          scopes: FIELD_SCOPES,
          description: "Latest checkpoint of the session." do
          argument :checkpoint_ns, GraphQL::Types::String,
            required: false,
            experiment: { milestone: '19.3' },
            description: 'LangGraph checkpoint namespace to scope the lookup to. ' \
              'Omit (or pass an empty string) for the session\'s own top-level checkpoint lineage; ' \
              'used internally to resolve one nested subgraph invocation, e.g. a delegated subagent.'
        end

        field :summary, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          description: 'Summary of the session.'

        field :title, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          description: 'Title of the session.'

        field :archived, GraphQL::Types::Boolean, method: :archived?,
          scopes: FIELD_SCOPES,
          description: 'Archived due to retention policy.'

        field :stalled, GraphQL::Types::Boolean,
          scopes: FIELD_SCOPES,
          description: 'Workflow got created but has no checkpoints.'

        field :last_executor_logs_url, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          description: "URL to the latest executor logs of the workflow."

        field :all_executor_logs_urls, [GraphQL::Types::String],
          scopes: FIELD_SCOPES,
          description: "List of all the executor logs for the workflow."

        field :ai_catalog_item_version_id, Types::GlobalIDType[::Ai::Catalog::ItemVersion],
          scopes: FIELD_SCOPES,
          null: true, description: 'ID of the AI catalog item version that triggered the workflow.',
          experiment: { milestone: '18.4' }

        # rubocop:disable GraphQL/ExtractType -- catalog item fields are intentionally kept flat for a consistent session-detail API
        field :ai_catalog_item, ::Types::Ai::Catalog::ItemInterface,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'AI catalog item (flow or agent definition) that the session ran.',
          experiment: { milestone: '19.4' }
        # rubocop:enable GraphQL/ExtractType

        field :trigger_source, Types::Ai::DuoWorkflows::WorkflowTriggerSourceEnum,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Kind of initiator that started the session.',
          experiment: { milestone: '19.6' }

        field :flow_trigger, ::Types::Ai::FlowTriggerType,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Flow trigger (automation) that started the session. Event-based sessions also have a ' \
            'trigger, so use `triggerSource` to detect scheduled sessions. Null when the trigger was deleted ' \
            'or the current user cannot read it.',
          experiment: { milestone: '19.6' }

        field :subagents, [Types::Ai::DuoWorkflows::SubagentType],
          scopes: FIELD_SCOPES,
          null: true,
          description: "Subagents provided to the session's latest run. " \
            "Null when GitLab doesn't know the session's subagents, for example for a session that runs " \
            'in the GitLab Duo CLI. This field can only be resolved for one session in any single request.',
          experiment: { milestone: '19.6' } do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        # rubocop:disable GraphQL/ExtractType -- no value for now
        field :resource_iid, GraphQL::Types::Int,
          scopes: FIELD_SCOPES,
          null: true, description: 'IID of the associated resource (issue or merge request).'

        field :resource_web_url, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true, description: 'Web URL of the associated resource (issue or merge request).'

        field :work_item, Types::WorkItemType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Associated work item (issue or epic), if any.'

        field :merge_request, Types::MergeRequestType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Associated merge request, if any.'
        # rubocop:enable GraphQL/ExtractType

        # rubocop:disable GraphQL/ExtractType -- links are a distinct connection with their own filter, not a sub-object of work_item
        field :work_item_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowWorkItemLinksResolver,
          scopes: FIELD_SCOPES,
          description: 'Work items linked to the session. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end
        # rubocop:enable GraphQL/ExtractType

        # rubocop:disable GraphQL/ExtractType -- links are a distinct connection with their own filter, not a sub-object of merge_request
        field :merge_request_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowMergeRequestLinksResolver,
          scopes: FIELD_SCOPES,
          description: 'Merge requests linked to the session. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end
        # rubocop:enable GraphQL/ExtractType

        field :note_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowNoteLinksResolver,
          scopes: FIELD_SCOPES,
          description: 'Notes linked to the session. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :pipeline_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowPipelineLinksResolver,
          scopes: FIELD_SCOPES,
          description: 'Pipelines linked to the session. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        # rubocop:disable GraphQL/ExtractType -- links are distinct connections with their own filter, not a sub-object
        field :workflow_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowWorkflowLinksResolver,
          scopes: FIELD_SCOPES,
          description: 'Other sessions linked to the session, for example the session it was restarted from. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :inverse_workflow_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowInverseWorkflowLinksResolver,
          scopes: FIELD_SCOPES,
          description: 'Other sessions that link to the session, for example the sessions restarted from it. ' \
            'On each link, `workflow` is the other session and `linkedWorkflow` is the session. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end
        # rubocop:enable GraphQL/ExtractType

        field :restarted_as, Types::Ai::DuoWorkflows::WorkflowType,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Newest session restarted from the session. ' \
            'Returns `null` when the session has not been restarted, ' \
            'or the current user cannot read its newest restart.',
          experiment: { milestone: '19.6' }

        field :agent_name, GraphQL::Types::String, # rubocop: disable GraphQL/ExtractType -- keeping agent fields flat for simpler API
          scopes: FIELD_SCOPES,
          null: true, description: 'Name of the agent used for the workflow.',
          experiment: { milestone: '18.8' }

        # rubocop:disable GraphQL/ExtractType -- model metadata fields are intentionally kept flat for a consistent session-detail API
        field :model_metadata_name, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true, description: 'Model used for the session.',
          experiment: { milestone: '19.2' }

        field :model_metadata_identifier, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Provider model identifier used for the session.',
          experiment: { milestone: '19.2' }
        # rubocop:enable GraphQL/ExtractType

        # rubocop:disable GraphQL/ExtractType -- flow_metadata fields are intentionally kept flat for a consistent session-detail API
        field :flow_metadata_version, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Version of the flow that was executed in the session.',
          experiment: { milestone: '19.3' }

        field :flow_metadata_id, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Identifier of the flow that was executed in the session.',
          experiment: { milestone: '19.3' }

        field :flow_metadata_schema_version, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Schema version of the flow metadata for the session.',
          experiment: { milestone: '19.3' }
        # rubocop:enable GraphQL/ExtractType

        # rubocop:disable GraphQL/ExtractType -- source_type and source_link are flat session-origin fields, not a sub-object
        field :source_type, Types::Ai::DuoWorkflows::WorkflowSourceTypeEnum,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Type of source that initiated the session.',
          experiment: { milestone: '19.4' }

        field :source_link, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'URL or deep link to the location where the session was triggered from.',
          experiment: { milestone: '19.4' }
        # rubocop:enable GraphQL/ExtractType

        field :user_permissions, Types::PermissionTypes::Ai::DuoWorkflows::Workflow, # rubocop: disable GraphQL/ExtractType -- user_id is intentionally separate as per comment above
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Permissions of the current user for the workflow.',
          method: :itself

        field :audit_events, ::Types::AuditEvents::AiAuditEventType.connection_type,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          authorize: :read_agent_artifacts,
          description: 'Audit events recorded for the session. ' \
            'Requires `read_agent_artifacts` on the workflow\'s project or namespace.',
          experiment: { milestone: '19.0' }

        # Like #latest_checkpoint below. The read gate still needs each
        # workflow's newest header, so that page-level load comes first.
        def first_checkpoint(checkpoint_ns: nil)
          ::BatchLoader::GraphQL.for([object, checkpoint_ns.presence]).batch do |keys, loader|
            workflows = keys.map { |presenter, _ns| presenter.workflow }.uniq(&:object_id)
            ::Ai::DuoWorkflows::Workflow.prime_latest_checkpoint_headers(workflows)

            keys.map(&:last).uniq.each do |ns|
              ns_workflows = keys.filter_map { |presenter, key_ns| presenter.workflow if key_ns == ns }
              ::Ai::DuoWorkflows::Workflow.prime_earliest_checkpoint_headers(
                ns_workflows.uniq(&:object_id), checkpoint_ns: ns
              )
            end
            prime_legacy_checkpoints(keys, newest: false)

            keys.each do |key|
              presenter, ns = key
              loader.call(key, presenter.first_checkpoint(checkpoint_ns: ns))
            end
          end
        end

        # Fetching the newest header row by row adds up on a list page; load
        # them for the whole page at once, and the legacy rows of the sessions
        # the read gate still serves from `p_duo_workflows_checkpoints` too.
        def latest_checkpoint(checkpoint_ns: nil)
          ::BatchLoader::GraphQL.for([object, checkpoint_ns.presence]).batch do |keys, loader|
            workflows = keys.map { |presenter, _ns| presenter.workflow }.uniq(&:object_id)
            ::Ai::DuoWorkflows::Workflow.prime_latest_checkpoint_headers(workflows)

            keys.filter_map(&:last).uniq.each do |ns|
              ns_workflows = keys.filter_map { |presenter, key_ns| presenter.workflow if key_ns == ns }
              ::Ai::DuoWorkflows::Workflow.prime_latest_checkpoint_headers(
                ns_workflows.uniq(&:object_id), checkpoint_ns: ns
              )
            end

            prime_legacy_checkpoints(keys, newest: true)

            keys.each do |key|
              presenter, ns = key
              loader.call(key, presenter.latest_checkpoint(checkpoint_ns: ns))
            end
          end
        end

        # The subagents come from the repository, and :read_duo_workflow doesn't imply :read_code: compliance
        # roles can read a session through :read_agent_artifacts.
        def subagents
          return unless Ability.allowed?(current_user, :read_code, object.project)

          ::Ai::DuoWorkflows::WorkloadAgents.new(object).list&.map do |agent|
            { name: agent['name'], description: agent['description'], tools: Array(agent['toolset']) }
          end
        end

        # Batch loaded so a page of workflows resolves checkpoint presence with one query
        # per checkpoint table instead of one query per workflow.
        def stalled
          return false if object.created?

          ::BatchLoader::GraphQL.for(object.workflow).batch do |workflows, loader|
            with_checkpoints = ::Ai::DuoWorkflows::Workflow.ids_with_checkpoints(workflows)

            workflows.each { |workflow| loader.call(workflow, with_checkpoints.exclude?(workflow.id)) }
          end
        end

        def restarted_as
          ::BatchLoader::GraphQL.for(object.id).batch do |workflow_ids, loader|
            restart_ids = ::Ai::DuoWorkflows::WorkflowWorkflow.newest_source_workflow_ids(workflow_ids)
            restarts = ::Ai::DuoWorkflows::Workflow.id_in(restart_ids.values).with_project_routes.index_by(&:id)

            restart_ids.each { |workflow_id, restart_id| loader.call(workflow_id, restarts[restart_id]) }
          end
        end

        def audit_events
          ::AuditEvents::AiAuditEvents::Finder.new(workflow: object).execute
        end

        def ai_catalog_item
          object.ai_catalog_item_version&.item
        end

        def drop_reason
          object.drop_reason if object.failed?
        end

        def web_path
          ::Gitlab::UrlBuilder.build(object, only_path: true)
        end

        def tool_call_approved(tool_name:, tool_call_args:)
          return false unless session_approval_usable?(tool_name)

          tool_call_approvals_object.approved?(tool_name: tool_name, call_args: tool_call_args)
        end

        def tool_call_approval_match(tool_name:, tool_call_args:)
          unless session_approval_usable?(tool_name)
            return ::Ai::DuoWorkflows::Workflow::ToolCallApprovals::NO_APPROVAL_MATCH
          end

          tool_call_approvals_object.approval_match(tool_name: tool_name, call_args: tool_call_args)
        end

        def allow_client_injected_mcp_tools
          ::Feature.enabled?(:dap_allow_client_injected_mcp_tools, root_namespace)
        end

        # Same actor as the frontend push, so the service rejects exactly what the
        # composer would not have offered.
        def file_attachments_allowed
          ::Ai::FileAttachments.allowed?(root_namespace, user: object.user)
        end

        def web_search_allowed
          ::Ai::DuoWorkflow.web_search_allowed?(object.project || object.namespace)
        end

        private

        # The sessions the read gate still serves from `p_duo_workflows_checkpoints`
        # get their newest or oldest row loaded per lineage for the whole page too.
        def prime_legacy_checkpoints(keys, newest:)
          keys.group_by(&:last).each do |ns, ns_keys|
            ns_workflows = ns_keys.map { |presenter, _ns| presenter.workflow }.uniq(&:object_id)

            if newest
              ::Ai::DuoWorkflows::Workflow.prime_latest_legacy_checkpoints(ns_workflows, checkpoint_ns: ns)
            else
              ::Ai::DuoWorkflows::Workflow.prime_earliest_legacy_checkpoints(ns_workflows, checkpoint_ns: ns)
            end
          end
        end

        def tool_call_approvals_object
          @tool_call_approvals_object ||= ::Ai::DuoWorkflows::Workflow::ToolCallApprovals.new(
            object.tool_call_approvals || {}
          )
        end

        # Checks the saved approvals first, so the policy is only resolved when one exists.
        def session_approval_usable?(tool_name)
          return false unless (object.tool_call_approvals || {}).key?(tool_name)

          tool_names_requiring_admin_approval.exclude?(tool_name)
        end

        def tool_names_requiring_admin_approval
          @tool_names_requiring_admin_approval ||=
            ::Ai::DuoWorkflows::ToolsRequiringAdminApprovalService.new(workflow: object).execute
        end

        def root_namespace
          (object.project || object.namespace)&.root_ancestor
        end
      end
    end
  end
end
