# frozen_string_literal: true

module Ai
  class FlowTrigger < ApplicationRecord
    include FromUnion
    include Gitlab::SQL::Pattern
    include Gitlab::Utils::StrongMemoize

    self.table_name = :ai_flow_triggers

    # Values match FLOW_TRIGGER_TYPES in ee/app/assets/javascripts/ai/duo_agents_platform/constants.js:
    # https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/assets/javascripts/ai/duo_agents_platform/constants.js#L186
    EVENT_TYPES = {
      mention: 0,
      assign: 1,
      assign_reviewer: 2,
      pipeline_hooks: 3,
      merge_request_ready: 4,
      merge_request_code_conflict: 5,
      merge_request: 6,
      work_item: 7,
      commit_to_default_branch: 8,
      scheduled: 9,
      security_policy: 10
    }.freeze

    EVENT_TYPES_BY_ID = EVENT_TYPES.invert.freeze

    RUN_STATUSES = {
      created: :pending,
      running: :running,
      paused: :awaiting_input,
      input_required: :awaiting_input,
      plan_approval_required: :awaiting_input,
      tool_call_approval_required: :awaiting_input,
      finished: :succeeded,
      failed: :failed,
      stopped: :canceled,
      idle: :succeeded
    }.freeze

    RUN_STATS_WINDOW = 30.days

    # Event types where every run is initiator-less, so the service account acts
    # alone. Only add a type if no run of it can have a human behind it: a cron
    # tick, or a scan that a security policy starts on its own schedule.
    AUTONOMOUS_EVENT_TYPE_IDS = [
      EVENT_TYPES[:scheduled],
      EVENT_TYPES[:security_policy]
    ].freeze

    SYSTEM_EVENT_TYPE_IDS = [
      EVENT_TYPES[:security_policy]
    ].freeze

    # Event types that a human action causes. On-finish settings apply only to a chain that one of these, a human
    # user's chat session, or a merge through GitLab by a human user started. Only add a type that no system process
    # can fire as a user. Automatic reviewer assignment runs as the author, so assign_reviewer is not here. A merged
    # trigger runs as the author, so merge_request is not here.
    HUMAN_ACTION_EVENT_TYPES = %w[mention assign work_item].freeze

    ALLOWED_FILTER_ACTIONS = {
      'merge_request' => %w[approved created merged pipeline_failed requested_changes].freeze,
      'work_item' => %w[created status_changed].freeze
    }.freeze

    # The fields of every event type of the merge request section of the trigger form.
    # Key paths must match Ai::FlowTriggers::MergeRequestFilterData.
    MERGE_REQUEST_FILTER_FIELDS = {
      # A flow session created the merge request.
      'created_by_flow' => [true, false].freeze,
      'draft' => [true, false].freeze
    }.freeze

    # Allowed rule fields per event type, and allowed values per field.
    # A nil value list means any value is allowed for that field.
    # Status values match PIPELINE_HOOK_STATUSES in ee/app/assets/javascripts/ai/duo_agents_platform/constants.js
    ALLOWED_FILTER_FIELDS = {
      'pipeline_hooks' => {
        'object_attributes.status' => %w[running success failed canceled].freeze,
        'object_attributes.source' => ::Enums::Ci::Pipeline.sources.keys.map(&:to_s).freeze,
        'object_attributes.ref' => nil,
        'object_attributes.default_branch' => [true, false].freeze,
        'merge_request.title' => nil
      }.freeze,
      'work_item' => {
        # action values are validated separately by filter_action_values_allowed.
        'action' => nil,
        # Key paths must match filter_data_extras in the work item workers and the filter data
        # in ApplyOnFinishSettingsWorker#still_matches_filter?.
        'status.name' => nil,
        # Type IDs depend on the namespace, so filter_work_item_type_ids_allowed validates them.
        'work_item_type_id' => nil,
        # The Software Factory marker, WorkItem#ai_planning_enabled?. The key names the concept and not the
        # column, so a rename of the column needs no change to the stored filters.
        'software_factory_enabled' => [true, false].freeze
      }.freeze,
      'merge_request' => {
        # action values are validated separately by filter_action_values_allowed.
        'action' => nil,
        **MERGE_REQUEST_FILTER_FIELDS
      }.freeze,
      'merge_request_code_conflict' => MERGE_REQUEST_FILTER_FIELDS,
      'merge_request_ready' => MERGE_REQUEST_FILTER_FIELDS
    }.freeze

    # Allowed operators per field, for each event type that allows the field. Fields not listed here take every
    # FilterEvaluator operator.
    FILTER_FIELD_OPERATORS = {
      # `in` also takes a single ID. FilterEvaluator compares `contains` as strings, so `contains 5` also
      # matches type 15, and `ne` compares a list as a whole, so `ne [5]` matches every type.
      'work_item_type_id' => %w[in not_in].freeze,
      # The trigger form reads and writes only `in` rules, and `not_in [true]` is the same as `in [false]`.
      'software_factory_enabled' => %w[in].freeze,
      'created_by_flow' => %w[in].freeze,
      'draft' => %w[in].freeze
    }.freeze

    # Fields that a new rule can use only when Gitlab::Ai::SoftwareFactory.enabled? for the container.
    SOFTWARE_FACTORY_FILTER_FIELDS = %w[software_factory_enabled created_by_flow draft].freeze

    # Set only on triggers that DAP Software Factory Sync creates and owns.
    enum :factory_stage, { triage: 0, plan: 1, build: 2, verify: 3, review: 4, ship: 5 }, prefix: :factory

    belongs_to :project, optional: true
    belongs_to :group, optional: true
    belongs_to :user
    belongs_to :ai_catalog_item_consumer, class_name: 'Ai::Catalog::ItemConsumer'
    # Held only by autonomous triggers. Separate from user_id so a catalog
    # trigger keeps the consumer's shared account untouched.
    belongs_to :autonomous_service_account, class_name: 'User', optional: true

    has_one :parent_item_consumer, through: :ai_catalog_item_consumer
    has_many :flow_schedules, class_name: 'Ai::FlowSchedule', foreign_key: :ai_flow_trigger_id,
      inverse_of: :flow_trigger

    scope :triggered_on, ->(event_type) { where("event_types @> ('{?}')", EVENT_TYPES[event_type]) }
    scope :not_triggered_on, ->(event_type) { where.not("event_types @> ('{?}')", EVENT_TYPES[event_type]) }
    scope :triggered_on_any, ->(event_types) {
      where('event_types && ARRAY[?]::smallint[]', EVENT_TYPES.values_at(*event_types))
    }
    # Skips autonomous triggers on purpose. Their dedicated account answers no
    # interactive event, so it must not surface in mention or assignment paths.
    scope :by_service_accounts, ->(service_accounts) {
      service_accounts = service_accounts.compact if service_accounts.is_a?(Array)

      from_union(
        [
          unscoped.where(user_id: service_accounts),
          unscoped.joins(:parent_item_consumer).where(parent_item_consumer: { service_account_id: service_accounts })
        ]
      )
    }
    scope :by_item_consumer_ids, ->(item_ids) { where(ai_catalog_item_consumer_id: item_ids) }
    scope :with_catalog_item_consumer, -> { where.not(ai_catalog_item_consumer_id: nil) }
    scope :ordered_by_id, -> { order(:id) }
    scope :for_foundational_flow_references, ->(references) {
      joins(ai_catalog_item_consumer: :item).where(ai_catalog_items: { foundational_flow_reference: references })
    }
    scope :for_projects, ->(project_ids) { where(project_id: project_ids) }
    scope :factory_managed, -> { where.not(factory_stage: nil) }
    scope :not_factory_managed, -> { where(factory_stage: nil) }
    scope :with_description, ->(description) { where(description: description) }
    scope :active, -> { where(active: true) }
    scope :inactive, -> { where(active: false) }
    scope :order_by_created, ->(direction) { reorder(created_at: direction, id: direction) }
    scope :order_by_updated, ->(direction) { reorder(updated_at: direction, id: direction) }

    def self.order_by_description(direction)
      name = Arel::Nodes::NamedFunction.new('LOWER', [arel_table[:description]])
      ascending = direction == :asc

      reorder(
        Gitlab::Pagination::Keyset::Order.build(
          [
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'description',
              order_expression: ascending ? name.asc : name.desc
            ),
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'id',
              order_expression: ascending ? arel_table[:id].asc : arel_table[:id].desc
            )
          ]
        )
      )
    end

    def self.with_last_run(workflows)
      schedules = ::Ai::FlowSchedule.arel_table
      last_session = runs_of_each_trigger(workflows).select(:created_at, :status).reorder(id: :desc).limit(1)
      last_failure = ::Ai::FlowSchedule.where(schedules[:ai_flow_trigger_id].eq(arel_table[:id]))
        .where.not(last_run_status: [nil, :success])
        .select(schedules[:last_run_at].maximum.as('last_run_at'))

      session = Arel::Table.new(:last_session)
      failure_at = Arel::Table.new(:last_failure)[:last_run_at]
      failure_is_last = failure_at.not_eq(nil).and(session[:created_at].eq(nil).or(failure_at.gt(session[:created_at])))

      with_run_columns(
        with_service_account_joins
          .joins("LEFT JOIN LATERAL (#{last_session.to_sql}) last_session ON TRUE")
          .joins("LEFT JOIN LATERAL (#{last_failure.to_sql}) last_failure ON TRUE")
          .select(
            Arel::Nodes::NamedFunction.new('GREATEST', [session[:created_at], failure_at]).as('last_run_at'),
            session[:status].as('last_session_status'),
            Arel::Nodes::Grouping.new(failure_is_last).as('last_run_is_schedule_failure')
          )
      )
    end

    def self.with_last_run_status(status)
      return where(last_run_at: nil) if status == :never

      states = ::Ai::DuoWorkflows::Workflow.state_machines[:status].states
      session_statuses = RUN_STATUSES.filter_map { |name, run_status| states[name].value if run_status == status }

      if status == :failed
        where(last_run_is_schedule_failure: true).or(where(last_session_status: session_statuses))
      else
        where(last_run_is_schedule_failure: false, last_session_status: session_statuses)
      end
    end

    def self.order_by_last_run(direction)
      last_run_at = arel_table[:last_run_at]
      ascending = direction == :asc

      reorder(
        Gitlab::Pagination::Keyset::Order.build(
          [
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'last_run_at',
              column_expression: last_run_at,
              order_expression: ascending ? last_run_at.asc.nulls_last : last_run_at.desc.nulls_last,
              reversed_order_expression: ascending ? last_run_at.desc.nulls_first : last_run_at.asc.nulls_first,
              order_direction: direction,
              nullable: :nulls_last
            ),
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'id',
              order_expression: ascending ? arel_table[:id].asc : arel_table[:id].desc
            )
          ]
        )
      )
    end

    def self.order_by_total_runs(workflows, direction)
      run_count = runs_of_each_trigger(workflows).reorder(nil).select(Arel.star.count.as('total_runs'))
      total_runs = arel_table[:total_runs]
      ascending = direction == :asc

      with_run_columns(
        with_service_account_joins
          .joins("LEFT JOIN LATERAL (#{run_count.to_sql}) runs ON TRUE")
          .select('runs.total_runs')
      ).reorder(
        Gitlab::Pagination::Keyset::Order.build(
          [
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'total_runs',
              order_expression: ascending ? total_runs.asc : total_runs.desc
            ),
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'id',
              order_expression: ascending ? arel_table[:id].asc : arel_table[:id].desc
            )
          ]
        )
      )
    end

    def self.with_run_columns(relation)
      unscoped.from(relation.select(arel_table[Arel.star]), table_name)
    end

    def self.with_service_account_joins
      consumers, parent_consumers = service_account_consumers

      joins(
        arel_table
          .join(consumers, Arel::Nodes::OuterJoin).on(consumers[:id].eq(arel_table[:ai_catalog_item_consumer_id]))
          .join(parent_consumers, Arel::Nodes::OuterJoin)
          .on(parent_consumers[:id].eq(consumers[:parent_item_consumer_id]))
          .join_sources
      )
    end

    def self.service_account_id_expression
      consumers, parent_consumers = service_account_consumers

      Arel::Nodes::NamedFunction.new(
        'COALESCE',
        [
          arel_table[:autonomous_service_account_id],
          consumers[:service_account_id],
          parent_consumers[:service_account_id],
          arel_table[:user_id]
        ]
      )
    end

    def self.service_account_consumers
      consumers = ::Ai::Catalog::ItemConsumer.arel_table

      [consumers.alias('trigger_consumers'), consumers.alias('trigger_parent_consumers')]
    end

    def self.runs_of_each_trigger(workflows)
      workflows_table = ::Ai::DuoWorkflows::Workflow.arel_table

      workflows
        .where(workflows_table[:trigger_flow_trigger_id].eq(arel_table[:id]))
        .where(workflows_table[:service_account_id].eq(service_account_id_expression))
    end

    private_class_method :with_run_columns, :with_service_account_joins, :service_account_id_expression,
      :service_account_consumers, :runs_of_each_trigger

    def self.search(term)
      item_name_match = ::Ai::Catalog::ItemConsumer
        .joins(:item)
        .where(::Ai::Catalog::ItemConsumer.arel_table[:id].eq(arel_table[:ai_catalog_item_consumer_id]))
        .where(::Ai::Catalog::Item.fuzzy_arel_match(:name, term, use_minimum_char_limit: false))
        .arel.exists

      where(
        fuzzy_arel_match(:description, term, use_minimum_char_limit: false)
          .or(fuzzy_arel_match(:config_path, term, use_minimum_char_limit: false))
          .or(item_name_match)
      )
    end

    # Firing-path guard: only active triggers count as registered.
    def self.registered_for?(project_id, event_type)
      return false unless project_id

      base = active.triggered_on(event_type)

      matched_project_id, matched_group_id = base.for_projects(project_id)
        .or(base.where(arel_table[:group_id].eq(root_group_id_subquery(project_id))))
        .order(arel_table[:project_id].asc.nulls_last)
        .pick(:project_id, :group_id)

      return true if matched_project_id
      return false unless matched_group_id

      Feature.enabled?(:ai_catalog_group_inherited_consumers, ::Group.actor_from_id(matched_group_id))
    end

    def self.applicable_to_container(container, by_service_accounts: nil, project_ids: nil)
      case container
      when ::Project
        applicable_to_project(container, by_service_accounts: by_service_accounts)
      when ::Namespace
        applicable_to_namespace(container, by_service_accounts: by_service_accounts, project_ids: project_ids)
      else
        none
      end
    end

    def self.applicable_to_project(project, triggered_on: nil, by_service_accounts: nil)
      return none unless project.is_a?(::Project)

      root_ancestor = project.root_ancestor
      base = apply_trigger_filters(for_projects(project.id), triggered_on: triggered_on)
      base = base.by_service_accounts(by_service_accounts) if by_service_accounts

      union_with_inherited(base, root_ancestor, triggered_on: triggered_on, by_service_accounts: by_service_accounts)
    end

    def self.applicable_to_namespace(namespace, by_service_accounts: nil, project_ids: nil)
      project_ids ||= namespace.project_ids
      root_ancestor = namespace.root_ancestor
      base = apply_trigger_filters(for_projects(project_ids))
      base = base.by_service_accounts(by_service_accounts) if by_service_accounts

      union_with_inherited(base, root_ancestor, triggered_on: nil, by_service_accounts: by_service_accounts)
    end

    def self.inherited_for_group(group)
      joins(:ai_catalog_item_consumer)
        .where(ai_catalog_item_consumers: { group_id: group.id, kind: :inheritance })
    end

    def self.union_with_inherited(base, root_ancestor, triggered_on:, by_service_accounts:)
      return base unless root_ancestor.is_a?(Group) &&
        Feature.enabled?(:ai_catalog_group_inherited_consumers, root_ancestor)

      inherited = apply_trigger_filters(inherited_for_group(root_ancestor), triggered_on: triggered_on)
      if by_service_accounts
        inherited = inherited.where(ai_catalog_item_consumers: { service_account_id: by_service_accounts })
      end

      from_union([base, inherited], remove_duplicates: false)
    end
    private_class_method :union_with_inherited

    private_class_method def self.root_group_id_subquery(project_id)
      root_group_query = ::Namespace
        .where(id: ::Project.where(id: project_id).select(:namespace_id))
        .select(Arel.sql('traversal_ids[1]'))

      Arel::Nodes::Grouping.new(root_group_query.arel)
    end

    def self.apply_trigger_filters(relation, triggered_on: nil)
      relation = relation.active
      relation = relation.triggered_on(triggered_on) if triggered_on
      relation
    end
    private_class_method :apply_trigger_filters

    validates :user, presence: true, unless: :ai_catalog_item_consumer
    validates :user, absence: true, if: :ai_catalog_item_consumer
    validates :autonomous_service_account, absence: true, unless: -> { event_types.blank? || autonomous_only? }
    # ItemConsumer builds triggers through nested attributes, bypassing the service
    # that assigns the account. Without this the trigger goes autonomous and
    # #service_account falls back to the consumer's shared, composite one.
    validates :autonomous_service_account, presence: true,
      if: -> { autonomous_only? && ai_catalog_item_consumer.present? }

    validates :event_types, presence: true
    validates :active, inclusion: { in: [true, false] }

    validates :description, length: { maximum: 255 }, presence: true
    validates :config_path, length: { maximum: 255 }, presence: true, unless: -> { ai_catalog_item_consumer.present? }

    validates :filter,
      json_schema: { filename: 'filter', size_limit: 8.kilobytes }

    before_validation :normalize_goals
    validates :goals,
      json_schema: { filename: 'ai_flow_trigger_goals', size_limit: 64.kilobytes, detail_errors: true }

    normalizes :status_on_finish, with: ->(value) { value.strip.presence }
    validates :status_on_finish, length: { maximum: 255 }
    validates :ready_merge_requests_on_finish, inclusion: { in: [true, false] }

    validates :ai_catalog_item_consumer, presence: true, unless: :config_path?

    # A group trigger has a NULL project_id, which the unique index on
    # (project_id, factory_stage) treats as distinct from every other NULL, so it would
    # escape the one-Managed-Trigger-per-stage rule.
    validates :factory_stage, absence: true, unless: :project_id?

    validate :event_types_are_valid
    validate :scheduled_event_type_available
    validate :scheduled_event_type_beta_available
    validate :scheduled_triggers_enabled_for_container
    validate :filter_keys_match_event_types
    validate :filter_action_values_allowed
    validate :filter_fields_and_values_allowed
    validate :filter_field_operators_allowed
    validate :filter_work_item_type_ids_allowed
    validate :filter_software_factory_fields_available
    validate :filter_pipeline_failed_action_for_developer
    validate :user_is_service_account, if: :user
    validates_with ExactlyOnePresentValidator, fields: [:config_path, :ai_catalog_item_consumer]
    validates_with ExactlyOnePresentValidator, fields: [:project, :group]
    validate :catalog_item_valid, if: -> { ai_catalog_item_consumer.present? }
    validate :supported_events_match_foundational_flow, if: -> { ai_catalog_item_consumer.present? }
    validate :consumer_must_have_active_service_account, if: :ai_catalog_item_consumer
    validate :event_types_not_mixed_with_autonomous
    validate :autonomous_account_not_composite, if: :autonomous_only?
    validate :group_trigger_belongs_to_inheritance_consumer, if: -> { group_id.present? }
    validate :group_trigger_not_autonomous, if: -> { group_id.present? && includes_autonomous? }
    validate :group_trigger_consumer_unchanged, if: -> { group_id.present? && persisted? }
    validate :autonomous_event_types_supported_by_target, if: :autonomous_only?
    validate :system_event_types_supported_by_target
    validate :goal_keys_match_event_types
    validate :goals_supported_by_target, if: -> { goals.present? }
    validate :on_finish_settings_need_status_changed_action, if: :applies_on_finish?

    scope :with_ids, ->(ids) { where(id: ids) }

    scope :include_parent_item_consumer, -> {
      includes(:parent_item_consumer)
    }

    def self.event_type_from_id(id)
      EVENT_TYPES_BY_ID[id]
    end

    def self.unsupported_schedule_target_message
      s_('AICatalog|Scheduled automations are not supported for this flow')
    end

    def self.mixed_event_types_message
      s_('AICatalog|Scheduled automations cannot be combined with other event types')
    end

    # Triggers backed by this account in this project. Project-scoped because
    # entitlement must not carry across projects. Callers add `.active`
    # themselves, and revocation deliberately does not: pausing is reversible
    # and nothing re-adds the membership on resume, while
    # AutonomousServiceAccountEligibilityValidator refuses to run without it.
    # Entitlement does chain `.active`, so a paused account keeps a membership
    # row and no Duo access.
    def self.for_autonomous_service_account(service_account, project)
      return none unless service_account && project

      where(autonomous_service_account_id: service_account.id).for_projects(project.id)
    end

    # Callable before a trigger exists, so services deciding whether to
    # provision a dedicated account share one definition with the model.
    def self.autonomous_only?(event_types)
      ids = Array(event_types).map(&:to_i)

      ids.present? && (ids - AUTONOMOUS_EVENT_TYPE_IDS).empty?
    end

    def self.includes_autonomous?(event_types)
      Array(event_types).map(&:to_i).intersect?(AUTONOMOUS_EVENT_TYPE_IDS)
    end

    def self.normalize_goals(goals)
      return {} if goals.nil?
      return goals unless goals.is_a?(Hash)

      goals.transform_values { |goal| goal.is_a?(String) ? goal.strip : goal }.reject { |_, goal| goal == '' }
    end

    # A trigger's own service account wins over the consumer's shared one, so an
    # autonomous trigger and an interactive trigger can sit on the same flow.
    def service_account_id
      return autonomous_service_account_id if autonomous_service_account_id.present?

      if for_ai_catalog_item_consumer?
        ai_catalog_item_consumer&.active_service_account_id
      else
        user_id
      end
    end

    def service_account
      return autonomous_service_account if autonomous_service_account.present?

      if for_ai_catalog_item_consumer?
        ai_catalog_item_consumer.active_service_account
      else
        user
      end
    end

    def container
      project || group
    end

    def scheduled_triggers_beta_available?(container = self.container)
      !!container&.root_ancestor&.duo_beta_flows_enabled?
    end

    # True when every event type runs without a human user, so the service account acts
    # alone. `BaseService` skips composite-identity enforcement for these, and
    # `FlowTriggers::RunService` requires it before allowing a caller's autonomous source.
    def autonomous_only?
      self.class.autonomous_only?(event_types)
    end

    def includes_autonomous?
      self.class.includes_autonomous?(event_types)
    end

    # Whether a cron tick fires this trigger. Separate from `autonomous_only?`, which
    # asks who the run acts as: the two coincide only while `scheduled` is the sole
    # autonomous event type.
    def scheduled?
      event_types&.include?(EVENT_TYPES[:scheduled]) || false
    end

    def foundational_flow
      ai_catalog_item_consumer&.item&.foundational_flow
    end
    strong_memoize_attr :foundational_flow

    # Some flow triggers give Duo Developer checks that other flows do not get.
    def developer_flow?
      foundational_flow&.foundational_flow_reference ==
        ::Ai::Catalog::FoundationalFlow.developer_v1.foundational_flow_reference
    end

    def foundational_flow_precondition
      foundational_flow&.precondition.presence
    end
    strong_memoize_attr :foundational_flow_precondition

    def goal_supported?
      item = ai_catalog_item_consumer&.item

      item.nil? || item.accepts_trigger_goal?
    end
    strong_memoize_attr :goal_supported?

    def schedulable_target?
      item = ai_catalog_item_consumer&.item

      item.present? && item.schedulable?
    end

    # The stored goal, not the composed one dispatch sends.
    def stored_goal_for(event_type)
      goals[event_type.to_s].presence
    end

    def applies_on_finish?
      status_on_finish.present? || ready_merge_requests_on_finish?
    end

    private

    def for_ai_catalog_item_consumer?
      ai_catalog_item_consumer_id.present? || ai_catalog_item_consumer.present?
    end

    def consumer_must_have_active_service_account
      return if ai_catalog_item_consumer.active_service_account.present?

      errors.add(:ai_catalog_item_consumer_id, "must have an active service account")
    end

    def event_types_are_valid
      return if event_types.blank?

      invalid_types = event_types - EVENT_TYPES.values
      return if invalid_types.empty?

      errors.add(:event_types, "contains invalid event types: #{invalid_types.join(', ')}")
    end

    def scheduled_event_type_available
      return unless newly_added_scheduled_event_type_present?
      return if Feature.enabled?(:autonomous_service_account_execution, project)

      errors.add(:event_types, 'scheduled events are not available')
    end

    def scheduled_event_type_beta_available
      return unless newly_added_scheduled_event_type_present?
      return if scheduled_triggers_beta_available?

      errors.add(:event_types, 'scheduled events require experiment and beta features')
    end

    def scheduled_triggers_enabled_for_container
      return unless newly_added_scheduled_event_type_present?
      return if container&.duo_scheduled_triggers_enabled

      errors.add(:event_types, 'scheduled events are turned off')
    end

    def newly_added_scheduled_event_type_present?
      scheduled? && newly_added_scheduled_event_type?
    end

    # A flag rollback must not break saves (e.g. deactivation) on triggers that already
    # have scheduled, only block creating new ones or adding it to existing triggers.
    # Method should be removed during autonomous_service_account_execution
    # FF clean up
    def newly_added_scheduled_event_type?
      return true if new_record?

      event_types_was.to_a.exclude?(EVENT_TYPES[:scheduled])
    end

    # Composite identity is a per-account flag, so a single trigger still cannot
    # serve both modes. Two triggers on one flow can, because each autonomous
    # trigger holds its own account. Per-execution account selection would lift
    # this too.
    def event_types_not_mixed_with_autonomous
      return if event_types.blank?

      autonomous = event_types & AUTONOMOUS_EVENT_TYPE_IDS
      return if autonomous.empty? || autonomous_only?

      names = autonomous.filter_map { |id| EVENT_TYPES_BY_ID[id] }.join(', ')
      errors.add(:event_types, "cannot combine autonomous event types (#{names}) with other event types. " \
        "Create a separate automation for them.")
    end

    def autonomous_event_types_supported_by_target
      return if autonomous_target? && (event_types.exclude?(EVENT_TYPES[:scheduled]) || schedulable_target?)
      # A row that predates this validation must stay saveable, or deactivating it is refused too.
      # The schedule worker blocks the run.
      return unless newly_unsupported_combination?

      errors.add(:base, self.class.unsupported_schedule_target_message)
    end

    def autonomous_target?
      item = ai_catalog_item_consumer&.item

      item.present? && !item.third_party_flow?
    end

    def newly_unsupported_combination?
      return true if new_record?

      event_types_changed? || ai_catalog_item_consumer_id_changed?
    end

    # A custom flow has no supported_events list, so a nil list must not admit
    # a system event type the way it admits any other type.
    def system_event_types_supported_by_target
      system_types = Array(event_types) & SYSTEM_EVENT_TYPE_IDS
      return if system_types.empty?
      return if (system_types - Array(foundational_flow&.supported_events)).empty?

      errors.add(:event_types, 'contains event types that only a foundational flow that supports them can use')
    end

    # Acting alone needs composite identity off, whichever account the trigger
    # runs as: its own for a catalog flow, user for a config_path trigger.
    def autonomous_account_not_composite
      return unless (autonomous_service_account || user)&.composite_identity_enforced?

      errors.add(:base, 'The service account for this automation must not have composite identity enforced')
    end

    # The column is NOT NULL with a '{}' default, so nil means "no goals".
    # Blank values would otherwise persist as a second, meaningless "unset" state.
    def normalize_goals
      self.goals = self.class.normalize_goals(goals)
    end

    def goals_supported_by_target
      return if goal_supported?
      # An item that is not a flow has no name to report, and catalog_item_valid
      # already refuses it.
      return unless foundational_flow

      errors.add(
        :base,
        format(
          s_('AICatalog|Instructions cannot be set for the %{flow_name} flow.'),
          flow_name: foundational_flow.translated_display_name
        )
      )
    end

    def goal_keys_match_event_types
      return if goals.blank?
      return unless goals.is_a?(Hash)

      unsupported_keys = goals.keys - active_event_type_keys

      return if unsupported_keys.empty?

      errors.add(
        :base,
        format(
          s_('AICatalog|Instructions cannot be set for an event type the trigger does not use: %{event_types}.'),
          event_types: unsupported_keys.join(', ')
        )
      )
    end

    def active_event_type_keys
      (event_types || []).filter_map { |id| EVENT_TYPES_BY_ID[id]&.to_s }
    end

    # The on-finish settings act on a session that a work item status change started. A session does
    # not record which work item action started it, so the trigger must not start on Created.
    # The worker re-checks the statuses when the session finishes, so the trigger must name them.
    def on_finish_settings_need_status_changed_action
      return if active_event_type_keys.include?('work_item') && status_changed_with_statuses?

      errors.add(:base, s_('AICatalog|On-finish settings require the work item event type with Status changed ' \
        'as its only action and at least one status.'))
    end

    # Mirrors how the trigger form reads the work item filter (parseFilterRuleValues): one top-level `in`
    # rule per field. The scope must match all rules, so the action rule excludes Created. Keep in step
    # with isWorkItemStatusChangedWithStatuses, the form's copy of this check.
    def status_changed_with_statuses?
      scope = filter['work_item'] if filter.is_a?(Hash)
      return false unless scope.is_a?(Hash)
      return false unless (scope['match'] || 'all') == 'all'

      statuses = top_level_in_values(scope, 'status.name')

      top_level_in_values(scope, 'action') == ['status_changed'] && statuses.is_a?(Array) && statuses.any?(String)
    end

    def top_level_in_values(scope, field)
      rules = Array(scope['rules']).select do |rule|
        rule.is_a?(Hash) && rule['field'] == field && rule['operator'] == 'in'
      end

      rules.first['value'] if rules.one?
    end

    # Checks filter top-level keys against event_types; nested rule shape and the object type are covered by the JSON
    # schema validator, so non-hash values fall through to that error rather than getting a duplicate one here.
    def filter_keys_match_event_types
      return if filter.blank?
      return unless filter.is_a?(Hash)

      unsupported_filter_keys = filter.keys - active_event_type_keys

      return if unsupported_filter_keys.empty?

      errors.add(:filter, "contains filters for event types not in event_types: #{unsupported_filter_keys.join(', ')}")
    end

    def filter_action_values_allowed
      return if filter.blank?
      return unless filter.is_a?(Hash)

      filter.each do |event_type_key, group|
        allowed = ALLOWED_FILTER_ACTIONS[event_type_key]
        next unless allowed

        blank_values, action_values = collect_action_values(group).partition(&:blank?)

        errors.add(:filter, "action values for #{event_type_key} can't be blank") unless blank_values.empty?

        invalid_values = action_values - allowed
        next if invalid_values.empty?

        errors.add(:filter,
          "contains invalid action values for #{event_type_key}: #{invalid_values.join(', ')}. " \
            "Allowed values are: #{allowed.join(', ')}")
      end
    end

    def collect_action_values(group)
      collect_leaf_rules(group)
        .select { |rule| rule['field'] == 'action' }
        .flat_map { |rule| rule_values(rule) }
    end

    def filter_fields_and_values_allowed
      return if filter.blank?
      return unless filter.is_a?(Hash)

      filter.each do |event_type_key, group|
        allowed_fields = ALLOWED_FILTER_FIELDS[event_type_key]
        next unless allowed_fields

        rules = collect_leaf_rules(group)

        validate_rule_fields(event_type_key, rules, allowed_fields)

        known_rules = rules.select { |rule| allowed_fields.key?(rule['field']) }
        validate_rule_value_presence(event_type_key, known_rules.reject { |rule| action_rule?(event_type_key, rule) })
        validate_rule_values(event_type_key, known_rules, allowed_fields)
      end
    end

    def validate_rule_fields(event_type_key, rules, allowed_fields)
      invalid_fields = rules.filter_map { |rule| rule['field'] unless allowed_fields.key?(rule['field']) }.uniq
      return if invalid_fields.empty?

      errors.add(:filter,
        "contains invalid fields for #{event_type_key}: #{invalid_fields.join(', ')}. " \
          "Allowed fields are: #{allowed_fields.keys.join(', ')}")
    end

    # Blank values (nil, empty strings, empty arrays) pass the JSON schema but
    # can never match an event, so reject them explicitly.
    def validate_rule_value_presence(event_type_key, rules)
      blank_fields = rules.filter_map { |rule| rule['field'] if blank_rule_value?(rule) }.uniq
      blank_fields.each do |field|
        errors.add(:filter, "#{field} values for #{event_type_key} can't be blank")
      end
    end

    # Blank action values are already reported by filter_action_values_allowed.
    def action_rule?(event_type_key, rule)
      ALLOWED_FILTER_ACTIONS.key?(event_type_key) && rule['field'] == 'action'
    end

    def validate_rule_values(event_type_key, rules, allowed_fields)
      allowed_fields.each do |field, allowed_values|
        next if allowed_values.nil? # any value is allowed for this field

        values = rules.select { |rule| rule['field'] == field }.flat_map { |rule| rule_values(rule) }
        invalid_values = values.reject { |value| blank_value?(value) }.uniq - allowed_values
        next if invalid_values.empty?

        errors.add(:filter,
          "contains invalid #{field} values for #{event_type_key}: #{invalid_values.join(', ')}. " \
            "Allowed values are: #{allowed_values.join(', ')}")
      end
    end

    def rule_values(rule)
      rule['value'].nil? ? [nil] : Array(rule['value'])
    end

    def blank_rule_value?(rule)
      blank_value?(rule['value']) || Array(rule['value']).any? { |value| blank_value?(value) }
    end

    # false is a meaningful filter value (object_attributes.default_branch), not a blank.
    def blank_value?(value)
      value != false && value.blank?
    end

    def filter_field_operators_allowed
      return unless filter.is_a?(Hash)

      filter.each_key do |event_type_key|
        allowed_fields = ALLOWED_FILTER_FIELDS.fetch(event_type_key, {})

        FILTER_FIELD_OPERATORS.slice(*allowed_fields.keys).each do |field, allowed_operators|
          validate_field_operators(event_type_key, field, allowed_operators)
        end
      end
    end

    def validate_field_operators(event_type_key, field, allowed_operators)
      invalid_operators = field_rules(filter, event_type_key, field).filter_map do |rule|
        rule['operator'] unless allowed_operators.include?(rule['operator'])
      end.uniq
      return if invalid_operators.empty?

      errors.add(:filter,
        "contains invalid #{field} operators for #{event_type_key}: #{invalid_operators.join(', ')}. " \
          "Allowed operators are: #{allowed_operators.join(', ')}")
    end

    # A string such as "5" passes the JSON schema but never equals the integer ID in the event.
    # Checks only the IDs that the change adds, so a stored ID that no longer resolves, for example
    # after a project transfer, does not block other edits.
    def filter_work_item_type_ids_allowed
      return unless container

      values = work_item_type_id_values(filter) - work_item_type_id_values(filter_in_database)
      return if values.empty?

      # `all` keeps archived types and the types that `filtered_types` hides, because their work items
      # still emit events. Work items of a converted type store the system-defined ID, hence persistable_id.
      invalid_values = values - ::WorkItems::TypesFramework::Provider.new(container).all.map(&:persistable_id)
      return if invalid_values.empty?

      errors.add(:filter,
        "contains invalid work_item_type_id values for work_item: #{invalid_values.map(&:inspect).join(', ')}. " \
          'Values must be integer IDs of work item types of the project or group')
    end

    # Checks only the rules that the change adds, so a stored rule does not block other edits after
    # the flag goes off.
    def filter_software_factory_fields_available
      added_fields = added_software_factory_fields
      return if added_fields.empty?
      return if container && ::Gitlab::Ai::SoftwareFactory.enabled?(container)

      added_fields.each do |event_type_key, field|
        errors.add(:filter, "#{field} rules for #{event_type_key} are not available")
      end
    end

    # Returns the [event_type_key, field] pairs that have a rule the change adds. The trigger form copies the rules of
    # its merge request section to each of its event types, so a rule stored under any event type that allows the
    # field is not new. A field that the event type does not allow gets only the filter_fields_and_values_allowed error.
    def added_software_factory_fields
      return [] unless filter.is_a?(Hash)

      filter.keys.product(SOFTWARE_FACTORY_FILTER_FIELDS).select do |event_type_key, field|
        next false unless ALLOWED_FILTER_FIELDS.fetch(event_type_key, {}).key?(field)

        # An event type without a field allowlist stores any rule without the flag, so its rules do not count.
        stored_rules = ALLOWED_FILTER_FIELDS.filter_map { |key, fields| key if fields.key?(field) }
          .flat_map { |key| field_rules(filter_in_database, key, field) }

        (field_rules(filter, event_type_key, field) - stored_rules).any?
      end
    end

    # Only the fix loop of Duo Developer starts a run for a failed pipeline, so a trigger of another flow that selects
    # the action would never run.
    def filter_pipeline_failed_action_for_developer
      return if developer_flow?

      selecting_operators = %w[eq in contains]
      selects_action = field_rules(filter, 'merge_request', 'action').any? do |rule|
        selecting_operators.include?(rule['operator']) && rule_values(rule).include?('pipeline_failed')
      end
      return unless selects_action

      errors.add(:filter, 'pipeline_failed action for merge_request is available only for Duo Developer')
    end

    def field_rules(filter_value, event_type_key, field)
      scope = filter_value[event_type_key] if filter_value.is_a?(Hash)

      collect_leaf_rules(scope).select { |rule| rule['field'] == field }
    end

    def work_item_type_id_values(filter_value)
      field_rules(filter_value, 'work_item', 'work_item_type_id')
        .flat_map { |rule| rule_values(rule) }
        .reject { |value| blank_value?(value) }
        .uniq
    end

    # Returns the leaf rule hashes of a filter group, descending into nested
    # groups up to Gitlab::FilterEvaluator::MAX_DEPTH.
    def collect_leaf_rules(group, depth = 1)
      return [] unless group.is_a?(Hash)
      return [] if depth > Gitlab::FilterEvaluator::MAX_DEPTH

      Array(group['rules']).flat_map do |rule|
        next [] unless rule.is_a?(Hash)

        rule['type'] == 'group' ? collect_leaf_rules(rule, depth + 1) : [rule]
      end
    end

    def user_is_service_account
      return if user.service_account?

      errors.add(:user, 'user must be a service account')
    end

    def catalog_item_valid
      if ai_catalog_item_consumer.container != container
        errors.add(:base, 'ai_catalog_item_consumer container does not match container')
      end

      return if ai_catalog_item_consumer.item.flow? || ai_catalog_item_consumer.item.third_party_flow?

      errors.add(:base, 'ai_catalog_item_consumer is not a flow')
    end

    def group_trigger_belongs_to_inheritance_consumer
      consumer = ai_catalog_item_consumer

      return if consumer.present? && consumer.inheritance? && consumer.group_id == group_id

      errors.add(:base, _('A group trigger must belong to an inheritance consumer of the same group'))
    end

    # Autonomous service accounts are not supported at the group level.
    def group_trigger_not_autonomous
      errors.add(:base, _('Scheduled automations are not supported for group configurations'))
    end

    # An inheritance consumer has one trigger. Moving it would leave its consumer
    # without a trigger and give the other consumer two.
    def group_trigger_consumer_unchanged
      return unless ai_catalog_item_consumer_id_changed?

      errors.add(:base, s_('AICatalog|The flow of a group trigger cannot be changed'))
    end

    def supported_events_match_foundational_flow
      supported = foundational_flow&.supported_events
      # A nil value means the flow has no event restrictions (any event is allowed). An empty array means the
      # flow explicitly supports no trigger events.
      return unless supported

      unsupported_event_types = event_types - supported
      if unsupported_event_types.any?
        errors.add(:event_types, "contains event types not supported by this foundational flow")
        return
      end

      return unless filter.is_a?(Hash)

      supported_keys = supported.map { |e| EVENT_TYPES.key(e).to_s }
      unsupported_filter_keys = filter.keys - supported_keys

      return unless unsupported_filter_keys.any?

      errors.add(:filter, "contains filters for unsupported event types: #{unsupported_filter_keys.join(', ')}")
    end
  end
end
