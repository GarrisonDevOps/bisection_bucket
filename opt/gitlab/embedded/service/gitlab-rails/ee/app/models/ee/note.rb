# frozen_string_literal: true

module EE
  module Note
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    SEARCH_WORK_ITEM_TRACKED_FIELDS = %w[note confidential].freeze

    prepended do
      include Elastic::ApplicationVersionedSearch
      include UsageStatistics

      has_one :duo_metadata, class_name: 'Notes::NoteDuoMetadata', inverse_of: :note

      has_many :duo_workflow_links,
        class_name: '::Ai::DuoWorkflows::WorkflowNote',
        foreign_key: :note_id,
        inverse_of: :note
      has_many :linked_duo_workflows,
        through: :duo_workflow_links,
        source: :workflow,
        disable_joins: true

      has_one :duo_created_workflow_link,
        -> { with_link_type(:created).order(:id) },
        class_name: '::Ai::DuoWorkflows::WorkflowNote',
        foreign_key: :note_id,
        inverse_of: :note

      has_one :duo_code_review_finding,
        class_name: '::Ai::DuoWorkflows::CodeReview::Finding',
        inverse_of: :note

      scope :searchable, -> { where(system: false).includes(:noteable) }
      scope :by_humans, -> { user.joins(:author).merge(::User.human) }
      scope :up_to_note, ->(note) { where('(notes.created_at, notes.id) <= (?, ?)', note.created_at, note.id) }
      scope :note_starting_with, ->(prefix) { where('note LIKE ?', "#{sanitize_sql_like(prefix)}%") }
      scope :created_by_duo_workflows, ->(workflows) do
        id_in(::Ai::DuoWorkflows::WorkflowNote.link_type_created.for_workflows(workflows).select(:note_id))
      end
      scope :count_for_vulnerability_id, ->(vulnerability_id) do
        where(noteable_type: ::Vulnerability.name, noteable_id: vulnerability_id)
          .group(:noteable_id)
          .count
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      override :use_separate_indices?
      def use_separate_indices?
        true
      end

      override :with_web_entity_associations
      def with_web_entity_associations
        super.preload(project: [:group, :project_feature, { namespace: :route }])
      end

      def inc_relations_for_view(noteable = nil)
        workflow_preloads = { workflow: [:user, { ai_catalog_item_version: :item }] }

        relation = super.preload({ system_note_metadata: { description_version: [:epic] } })
                        .preload({ duo_metadata: workflow_preloads })
                        .preload(duo_workflow_links: workflow_preloads)
                        .preload(duo_created_workflow_link: workflow_preloads)

        # Findings only exist on merge request comments.
        return relation unless noteable.is_a?(::MergeRequest)

        relation.preload(
          :duo_code_review_finding,
          duo_created_workflow_link: { workflow: [:code_review_findings, { created_note_links: :note }] }
        )
      end
    end

    override :use_elasticsearch?
    def use_elasticsearch?
      !system && super
    end

    def for_epic?
      noteable.is_a?(Epic)
    end

    def for_group_wiki?
      for_wiki_page? && noteable&.for_group_wiki?
    end

    def for_vulnerability?
      noteable.is_a?(Vulnerability)
    end

    override :for_project_noteable?
    def for_project_noteable?
      !(for_epic? || for_group_wiki?) && super
    end

    override :banzai_render_context
    def banzai_render_context(field)
      return super unless for_epic?

      super.merge(banzai_epic_context_params)
    end

    override :mentionable_params
    def mentionable_params
      return super unless for_epic?

      super.merge(banzai_epic_context_params)
    end

    override :store_mentions?
    def store_mentions?
      noteable_type != 'ComplianceManagement::Projects::ComplianceViolation'
    end

    override :trigger_note_subscription?
    def trigger_note_subscription?
      super || for_compliance_violation?
    end

    override :trigger_note_subscription_create
    def trigger_note_subscription_create
      return super unless for_compliance_violation?

      ::GraphqlTriggers.work_item_note_created(noteable.to_global_id, self)
    end

    override :trigger_note_subscription_update
    def trigger_note_subscription_update
      return super unless for_compliance_violation?

      ::GraphqlTriggers.work_item_note_updated(noteable.to_global_id, self)
    end

    override :trigger_note_subscription_destroy
    def trigger_note_subscription_destroy
      return super unless for_compliance_violation?

      deleted_note_data = {
        id: id,
        model_name: self.class.name,
        discussion_id: discussion_id,
        last_discussion_note: discussion.notes.count == 1
      }

      ::GraphqlTriggers.work_item_note_deleted(noteable.to_global_id, deleted_note_data)
    end

    override :store_mentions_after_commit?
    def store_mentions_after_commit?
      user_mention_class == VulnerabilityUserMention
    end

    override :for_issuable?
    def for_issuable?
      for_epic? || super
    end

    override :system_note_visible_for?
    def system_note_visible_for?(user)
      return false unless super
      return false if system_note_for_decision? && !decision_log_visible_for?(user)
      return false if system_note_for_workplan? && !workplan_visible_for?(user)

      return true unless system_note_for_epic? && created_before_noteable?

      group_reporter?(user, noteable.group)
    end

    override :skip_notification?
    def skip_notification?
      for_vulnerability? || super
    end

    override :touch_noteable
    def touch_noteable
      return super unless for_epic?

      assoc = association(:noteable)
      noteable_object = assoc.loaded? ? noteable : assoc.scope.select(:id, :updated_at, :issue_id, :group_id, :iid).take

      noteable_object&.touch
      # Ensure epic and work items are kept in sync after creating notes on the epic
      noteable_object&.sync_work_item_updated_at

      noteable_object
    end

    def usage_ping_track_updated_epic_note(user)
      return unless for_epic?

      ::Gitlab::UsageDataCounters::EpicActivityUniqueCounter.track_epic_note_updated_action(
        author: user,
        namespace: noteable.group
      )
    end

    def updated_by_or_author
      updated_by || author
    end

    override :maintain_elasticsearch_create
    def maintain_elasticsearch_create
      super

      update_work_item_for_note!
    end

    override :maintain_elasticsearch_update
    def maintain_elasticsearch_update(updated_attributes: previous_changes.keys)
      super

      update_work_item_for_note! if (updated_attributes & SEARCH_WORK_ITEM_TRACKED_FIELDS).any?
    end

    override :maintain_elasticsearch_destroy
    def maintain_elasticsearch_destroy
      super

      update_work_item_for_note!
    end

    def authored_by_duo_bot?
      author.duo_code_review_bot?
    end

    def duo_bot_mentioned?
      # We don't want the bot to talk to itself
      return false if authored_by_duo_bot?

      mentioned_users.any?(&:duo_code_review_bot?)
    end

    def agent_session
      workflow = duo_created_workflow_link&.workflow
      workflow if workflow&.service_account_id
    end

    override :human_max_access
    def human_max_access
      return super unless project.blank? && for_group_wiki?

      ::Gitlab::Access.human_access(namespace.max_member_access_for_user(author))
    end

    private

    def update_work_item_for_note!
      return unless for_work_item?
      return unless noteable.maintaining_elasticsearch?

      ::Elastic::ProcessBookkeepingService.track!(noteable)
    end

    override :ensure_namespace_id
    def ensure_namespace_id
      return super unless for_epic? || for_group_wiki?

      # Epic and group-wiki notes are keyed solely by namespace_id; clear the
      # other sharding keys so the row satisfies num_nonnulls(...) = 1 even if a
      # project was assigned upstream. Recomputed every validation to repair
      # existing rows on update. See https://gitlab.com/gitlab-org/gitlab/-/issues/601435
      self.project = nil
      self.organization_id = nil
      self.namespace_id = for_group_wiki? ? noteable&.namespace_id : noteable&.group_id
    end

    def system_note_for_epic?
      system? && for_epic?
    end

    def created_before_noteable?
      created_at.to_i < noteable.created_at.to_i
    end

    def group_reporter?(user, group)
      group.max_member_access_for_user(user) >= ::Gitlab::Access::REPORTER
    end

    def system_note_for_decision?
      system? && for_issue? && system_note_metadata&.action == 'decision_recorded'
    end

    # Decision notes are shown only to users who can see the decision log widget.
    # A note loads its noteable as an Issue, but the ability exists only on WorkItemPolicy
    def decision_log_visible_for?(user)
      work_item = noteable.becomes(::WorkItem) # rubocop:disable Cop/AvoidBecomes -- ability is only on WorkItemPolicy
      return false unless work_item.get_widget(:decision_log)

      ::Ability.allowed?(user, ::WorkItems::Widgets::DecisionLog.required_user_ability, work_item)
    end

    def system_note_for_workplan?
      system? && for_issue? && system_note_metadata&.action == 'workplan'
    end

    def workplan_visible_for?(user)
      work_item = noteable.becomes(::WorkItem) # rubocop:disable Cop/AvoidBecomes -- ability is only on WorkItemPolicy
      return false unless work_item.get_widget(:agent_plan)

      ::Ability.allowed?(user, ::WorkItems::Widgets::AgentPlan.required_user_ability, work_item)
    end

    def banzai_epic_context_params
      { label_url_method: :group_epics_url }
    end
  end
end
