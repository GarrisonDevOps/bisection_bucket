# frozen_string_literal: true

module EE
  module Issue
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    prepended do
      WEIGHT_RANGE = (0..20)
      WEIGHT_ALL = 'Everything'
      WEIGHT_ANY = 'Any'
      WEIGHT_NONE = 'None'
      ELASTICSEARCH_PERMISSION_TRACKED_FIELDS = %w[assignee_ids author_id confidential].freeze
      BLOCKING_ISSUES_COUNT_BATCH_SIZE = 100

      include ::Elastic::ApplicationVersionedSearch
      include UsageStatistics
      include IterationEventable
      include HealthStatus
      include Epics::MetadataCacheUpdate
      # widget supporting custom issue types - see https://gitlab.com/gitlab-org/gitlab/-/issues/292035
      include IssueWidgets::ActsLikeRequirement

      # we'd need to make sure these override the existing associations so we prepend this.
      include ::WorkItems::EpicAsWorkItem
      include ::WorkItems::HasStatus

      scope :order_blocking_issues_asc, -> { reorder(blocking_issues_count: :asc) }
      scope :order_blocking_issues_desc, -> { reorder(blocking_issues_count: :desc) }
      scope :order_weight_desc, -> { reorder(arel_table[:weight].desc.nulls_last) }
      scope :order_weight_asc, -> { reorder(arel_table[:weight].asc.nulls_last) }
      scope :order_health_status_desc, -> { reorder(arel_table[:health_status].desc.nulls_last) }
      scope :order_health_status_asc, -> { reorder(arel_table[:health_status].asc.nulls_last) }
      scope :order_status_page_published_first, -> do
        build_keyset_order_on_joined_column(
          scope: includes(:status_page_published_incident),
          attribute_name: 'published_incidents_id',
          column: StatusPage::PublishedIncident.arel_table[:id],
          direction: :asc,
          nullable: :nulls_last
        )
      end
      scope :order_status_page_published_last, -> do
        build_keyset_order_on_joined_column(
          scope: includes(:status_page_published_incident),
          attribute_name: 'published_incidents_id',
          column: StatusPage::PublishedIncident.arel_table[:id],
          direction: :desc,
          nullable: :nulls_first
        )
      end
      scope :order_sla_due_at_asc, -> do
        build_keyset_order_on_joined_column(
          scope: includes(:issuable_sla),
          attribute_name: 'issuable_slas_due_at',
          column: IssuableSla.arel_table[:due_at],
          direction: :asc,
          nullable: :nulls_last
        )
      end
      scope :order_sla_due_at_desc, -> do
        build_keyset_order_on_joined_column(
          scope: includes(:issuable_sla),
          attribute_name: 'issuable_slas_due_at',
          column: IssuableSla.arel_table[:due_at],
          direction: :desc,
          nullable: :nulls_last
        )
      end
      scope :without_weights, ->(weights) { where(weight: nil).or(where.not(weight: weights)) }
      scope :no_epic, -> { left_outer_joins(:epic_issue).where(epic_issues: { epic_id: nil }) }
      scope :any_epic, -> { joins(:epic_issue) }
      scope :in_epics, ->(epics) { joins(:epic_issue).where(epic_issues: { epic_id: epics }) }
      scope :not_in_epics, ->(epics) { left_outer_joins(:epic_issue).where('epic_issues.epic_id NOT IN (?) OR epic_issues.epic_id IS NULL', epics) }
      scope :sorted_by_epic_position, -> { joins(:epic_issue).select('issues.*, epic_issues.id as epic_issue_id, epic_issues.relative_position, epic_issues.epic_id as epic_id').order('epic_issues.relative_position, epic_issues.id') }
      scope :no_iteration, -> { where(sprint_id: nil) }
      scope :any_iteration, -> { where.not(sprint_id: nil) }
      scope :in_iterations, ->(iterations) { where(sprint_id: iterations) }
      scope :not_in_iterations, ->(iterations) { where(sprint_id: nil).or(where.not(sprint_id: iterations)) }
      scope :in_iteration_scope, ->(iteration_scope) { joins(:iteration).merge(iteration_scope) }
      scope :in_iteration_cadences, ->(iteration_cadences) { joins(:iteration).where(sprints: { iterations_cadence_id: iteration_cadences }) }
      scope :with_iteration_title, ->(iteration_title) { joins(:iteration).where(sprints: { title: iteration_title }) }
      scope :without_iteration_title, ->(iteration_title) { left_outer_joins(:iteration).where('sprints.title IS DISTINCT FROM ?', iteration_title) }
      scope :on_status_page, -> do
        joins(project: :status_page_setting)
        .where(status_page_settings: { enabled: true })
        .joins(:status_page_published_incident)
        .public_only
      end
      scope :counts_by_health_status, -> { reorder(nil).group(:health_status).count }
      scope :with_health_status, ->(status) { where(health_status: status) }
      scope :with_any_health_status, -> { where.not(health_status: nil) }
      scope :with_no_health_status, -> { where(health_status: nil) }
      scope :without_health_status, ->(status) { where(health_status: nil).or(where.not(health_status: status)) }

      scope :distinct_epic_ids, -> do
        epic_ids = except(:order, :select).joins(:epic_issue).reselect('epic_issues.epic_id').distinct
        epic_ids = epic_ids.group('epic_issues.epic_id') if epic_ids.group_values.present?

        epic_ids
      end

      scope :preload_search_data, -> do
        preload(
          :labels,
          :timelogs,
          :assignees,
          :synced_epic,
          project: [:route, { namespace: [:route, :parent] }, :group],
          namespace: [:route, :parent]
        )
      end
      # Excludes group level epics: `Epic` writes the same work_items document
      # through its own `elastic_reference`, so tracking the row here too would
      # double-track it. Row predicate, not a subquery, to stay index-only.
      scope :searchable, -> { where.not(project_id: nil).or(without_issue_type(:epic)) }
      scope :preload_iteration, -> { preload(:iteration) }

      belongs_to :iteration, foreign_key: 'sprint_id', inverse_of: :issues

      has_one :epic_issue
      has_one :epic, through: :epic_issue

      has_one :status_page_published_incident, class_name: 'StatusPage::PublishedIncident', inverse_of: :issue
      has_one :issuable_sla
      has_many :metric_images, class_name: 'IssuableMetricImage'

      has_many :vulnerability_links, class_name: 'Vulnerabilities::IssueLink', inverse_of: :issue
      has_many :related_vulnerabilities, through: :vulnerability_links, source: :vulnerability

      has_many :duo_workflows, class_name: '::Ai::DuoWorkflows::Workflow', inverse_of: :issue

      has_many :feature_flag_issues
      has_many :feature_flags,
        through: :feature_flag_issues,
        class_name: '::Operations::FeatureFlag',
        inverse_of: :issues

      has_many :pending_escalations, class_name: 'IncidentManagement::PendingEscalations::Issue', foreign_key: :issue_id, inverse_of: :issue

      has_many :issuable_resource_links, class_name: 'IncidentManagement::IssuableResourceLink', inverse_of: :issue

      has_many :resource_weight_events
      has_many :issue_stage_events, class_name: 'Analytics::CycleAnalytics::IssueStageEvent'

      has_many :observability_metrics, class_name: 'Observability::MetricsIssuesConnection', inverse_of: :issue
      has_many :observability_logs, class_name: 'Observability::LogsIssuesConnection', inverse_of: :issue
      has_many :observability_traces, class_name: 'Observability::TracesIssuesConnection', inverse_of: :issue

      has_one :sync_object, class_name: 'Epic', foreign_key: 'issue_id', inverse_of: :sync_object
      # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
      has_one :synced_epic, class_name: 'Epic', foreign_key: 'issue_id', inverse_of: :work_item, dependent: :destroy
      # rubocop:enable Cop/ActiveRecordDependent -- legacy usage

      validates :weight, allow_nil: true, numericality: { greater_than_or_equal_to: 0 }
      validate :validate_confidential_epic

      state_machine :state_id do
        after_transition do |issue|
          issue.refresh_blocking_and_blocked_issues_cache!
        end
      end

      before_destroy :set_old_epic_id
      before_destroy :refresh_blocking_issues_count_after_destroy
      after_save :set_epic_id_to_update_cache

      delegate :promoted_to_epic, to: :work_item_transition, allow_nil: true

      Dora::Watchers.mount(self)
    end

    class_methods do
      def with_web_entity_associations
        super.preload(project: :invited_groups)
      end

      def with_api_entity_associations
        super.preload(:sync_object, epic: { group: :route }, iteration: { group: :route })
      end

      # override
      def supported_keyset_orderings
        super.merge(weight: [:asc, :desc])
      end

      def es_type
        ::Search::Elastic::References::WorkItem::DOC_TYPE
      end
    end

    def promoted_to_epic=(epic)
      self.promoted_to_epic_id = epic&.id
    end

    # override
    def allows_multiple_assignees?
      licensed_feature_available?(:multiple_issue_assignees)
    end

    def blocked?
      blocking_issues_ids.any?
    end

    def blocked_by_issues
      self.class.where(id: blocking_issues_ids)
    end

    # Used on EE::IssueEntity to expose blocking issues URLs
    def blocked_by_issues_for(user)
      return ::Issue.none unless blocked?

      issues =
        ::IssuesFinder.new(user).execute.where(id: blocking_issues_ids)

      issues.preload(project: [:route, { namespace: [:route] }])
    end

    # override
    def weight
      super if weight_available?
    end

    def es_parent
      "group_#{namespace.root_ancestor.id}"
    end

    def es_id
      ::Search::Elastic::Helper.build_es_id(es_type: es_type, target_id: id)
    end

    override :elastic_reference
    def elastic_reference
      ::Search::Elastic::References::WorkItem.serialize(self)
    end

    override :maintain_elasticsearch_update
    def maintain_elasticsearch_update(updated_attributes: previous_changes.keys)
      super

      maintain_elasticsearch_issue_notes_update if elasticsearch_issue_notes_need_updating?
    end

    def maintain_elasticsearch_issue_notes_update
      ::Note.searchable.where(noteable: self).find_each do |note|
        note.maintain_elasticsearch_update
      end
    end

    def elasticsearch_issue_notes_need_updating?
      changed_fields = self.previous_changes.keys
      changed_fields && (changed_fields & ELASTICSEARCH_PERMISSION_TRACKED_FIELDS).any?
    end

    override :supports_weight?
    def supports_weight?
      return false if work_item_type&.incident?

      true
    end

    override :weight_available?
    def weight_available?
      super && resource_parent&.licensed_feature_available?(:issue_weights)
    end

    override :supports_iterations?
    def supports_iterations?
      true
    end

    def can_be_promoted_to_epic?(user, group = nil)
      group ||= project.group

      return false unless user
      return false unless group

      persisted? && supports_epic? && !work_item_transition.promoted? &&
        Ability.allowed?(user, :admin_issue, project) && Ability.allowed?(user, :create_epic, group)
    end

    override :clear_closure_reason_references
    def clear_closure_reason_references
      super

      self.promoted_to_epic_id = nil
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      override :simple_sorts
      def simple_sorts
        super.merge(
          {
            'weight' => -> { order_weight_asc.with_order_id_desc },
            'weight_asc' => -> { order_weight_asc.with_order_id_desc },
            'weight_desc' => -> { order_weight_desc.with_order_id_desc }
          }
        )
      end

      override :sort_by_attribute
      def sort_by_attribute(method, excluded_labels: [])
        case method.to_s
        # aliases for blocking_issues
        when 'blocking_issues_asc' then order_blocking_issues_asc.with_order_id_desc
        when 'blocking_issues_desc' then order_blocking_issues_desc.with_order_id_desc
        when 'weight', 'weight_asc' then order_weight_asc.with_order_id_desc
        when 'weight_desc'          then order_weight_desc.with_order_id_desc
        when 'published_asc'        then order_status_page_published_last
        when 'published_desc'       then order_status_page_published_first
        when 'sla_due_at_asc'       then with_feature(:sla).order_sla_due_at_asc
        when 'sla_due_at_desc'      then with_feature(:sla).order_sla_due_at_desc
        when 'health_status_asc'    then order_health_status_asc
        when 'health_status_desc'   then order_health_status_desc
        when 'status_asc'           then order_status_asc
        when 'status_desc'          then order_status_desc
        else
          super
        end
      end

      def weight_options
        [WEIGHT_NONE, WEIGHT_ANY] + WEIGHT_RANGE.to_a
      end

      # Recounts issues whose blocked issues were deleted by a cascade, after
      # the delete is committed: an issue that cannot be saved keeps its count.
      def update_blocking_issues_count_for(issue_ids)
        issue_ids.each_slice(BLOCKING_ISSUES_COUNT_BATCH_SIZE) do |batch_ids|
          id_in(batch_ids).find_each do |blocking_issue|
            blocking_issue.update_blocking_issues_count!
          rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotSaved => e
            ::Gitlab::ErrorTracking.track_exception(e, issue_id: blocking_issue.id)
          end
        end
      end
    end

    def update_blocking_issues_count!
      # No-op on frozen records: production records are never frozen,
      # so this only guards frozen shared test fixtures from a lazy write.
      return if frozen?

      blocking_count = self.class.related_link_class.blocking_issuables_count_for(self)

      update!(blocking_issues_count: blocking_count)
    end

    def refresh_blocking_and_blocked_issues_cache!
      link_class = self.class.related_link_class
      # Closed blockers count this issue too, so recount them, not only the open ones in blocking_issues_ids.
      blocking_ids = link_class.blocks.for_target(self).limit(link_class::MAX_LINKS_COUNT).pluck(:source_id)
      blocking_issues_count_by_id = link_class.blocking_issuables_for_collection([id] + blocking_ids).to_sql

      self.class.connection.execute <<~SQL
        UPDATE issues
        SET blocking_issues_count = grouped_counts.count
        FROM (#{blocking_issues_count_by_id}) AS grouped_counts
        WHERE issues.id = grouped_counts.blocking_issue_id
      SQL
    end

    def related_feature_flags(current_user, preload: nil)
      feature_flags = ::Operations::FeatureFlag
        .select('operations_feature_flags.*, operations_feature_flags_issues.id AS link_id')
        .joins(:feature_flag_issues)
        .where(operations_feature_flags_issues: { issue_id: id })
        .order('operations_feature_flags_issues.id ASC')
        .includes(preload)

      cross_project_filter = ->(feature_flags) { feature_flags.where(project: project) }
      Ability.feature_flags_readable_by_user(feature_flags,
        current_user,
        filters: { read_cross_project: cross_project_filter })
    end

    override :relocation_target
    def relocation_target
      super || promoted_to_epic
    end

    override :supports_epic?
    def supports_epic?
      issue_type_supports?(:epics) && project.group.present?
    end

    override :update_upvotes_count
    def update_upvotes_count
      super
      return unless maintaining_elasticsearch?

      self.class.current_transaction.after_commit do
        maintain_elasticsearch_update(updated_attributes: ['upvotes_count'])
      end
    end

    def has_epic?
      epic_issue.present?
    end

    def has_parent_link?
      # the WorkItems::ParentLink#validate_legacy_hierarchy validation only allows one type of parent at a time so we
      # don't expect a parent work item if the issue is already assigned to an epic. There is one exception for epics
      # that have synced work items, but those cases should ignore the parent link in favour of returning the epic.
      return false if has_epic?

      existing_relation = ::WorkItems::ParentLink.find_by_work_item_id(id)
      existing_relation.present?
    end

    def licensed_feature_available?(feature)
      return project.licensed_feature_available?(feature) if project

      namespace.licensed_feature_available?(feature)
    end

    override :sla_available?
    def sla_available?
      return false unless ::IncidentManagement::IncidentSla.available_for?(self)

      supports_sla?
    end

    override :supports_parent?
    def supports_parent?
      supports_epic? && licensed_feature_available?(:epics)
    end

    # WorkItems only
    # - OKRs (objectives and key results) only work with WorkItems views.
    # - Epics only work with WorkItems views.
    override :show_as_work_item?
    def show_as_work_item?
      return true if work_item_type&.epic?
      return okr_available_and_enabled? if okr_work_item? # OKRs

      super
    end

    override :use_work_item_url?
    def use_work_item_url?
      return okr_available_and_enabled? if okr_work_item? # OKRs
      return true if epic_work_item? && !group_level? # Project epics

      super
    end

    override :work_item_type
    def work_item_type
      super || out_of_scope_custom_type_fallback
    end

    override :epic_work_item?
    def epic_work_item?
      return false unless work_item_type

      work_item_type.epic?
    end

    private

    def out_of_scope_custom_type_fallback
      custom_type = ::WorkItems::TypesFramework::Custom::Type.find_by_id(work_item_type_id)
      return unless custom_type

      # Match by name first so the item keeps a same-named type and its lifecycle.
      work_items_types_provider.all.find { |type| type.name.casecmp?(custom_type.name) } ||
        work_items_types_provider.find_by_base_type(custom_type.base_type)
    end
    strong_memoize_attr :out_of_scope_custom_type_fallback

    def okr_work_item?
      work_item_type&.objective? || work_item_type&.key_result?
    end

    def okr_available_and_enabled?
      licensed_feature_available?(:okrs) && resource_parent.okrs_mvc_feature_flag_enabled?
    end

    def blocking_issues_ids
      @blocking_issues_ids ||= self.class.related_link_class.blocking_issuables_ids_for(self)
    end

    def validate_confidential_epic
      return unless epic

      if !confidential? && epic.confidential?
        errors.add :base, confidentiality_error
      end
    end

    def confidentiality_error
      if changed_attribute_names_to_save.include?('confidential')
        return _('This issue cannot be made public because it belongs to a confidential epic.')
      end

      _('This issue cannot be assigned to a confidential epic because it is public.')
    end

    def set_old_epic_id
      register_epic_id_for_cache_update(epic_issue.epic_id) if epic_issue
    end

    def set_epic_id_to_update_cache
      return unless weight_previously_changed? || state_id_previously_changed?
      return unless epic_issue

      register_epic_id_for_cache_update(epic_issue.epic_id)
    end

    # The links that point at this issue are removed by an ON DELETE CASCADE
    # foreign key, which runs no link callback, so the issues it was blocked by
    # are read before the delete and recounted once it is committed. Blockers
    # count only open issues, so deleting a closed one changes no count.
    def refresh_blocking_issues_count_after_destroy
      return unless opened?

      link_class = self.class.related_link_class
      blocking_issue_ids = link_class.blocks.for_target(self).limit(link_class::MAX_LINKS_COUNT).pluck(:source_id)
      return if blocking_issue_ids.empty?

      run_after_commit do
        self.class.update_blocking_issues_count_for(blocking_issue_ids)
      end
    end

    override :allowed_work_item_type_change
    def allowed_work_item_type_change
      super

      # We don't allow any other type than Issues for Epics. However, as this restriction got introduced
      # afterwards, there is the possibility that other issue types (e.g. Incident) exist with an epic assigned.
      # To not invalidate these records, we only check type changes for Issues.
      return unless has_epic? && !work_item_type.issue?

      errors.add(:work_item_type_id, format(_('can not be changed when assigned to an epic')))
    end
  end
end
