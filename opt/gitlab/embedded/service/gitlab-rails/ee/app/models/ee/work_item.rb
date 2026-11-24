# frozen_string_literal: true

module EE
  module WorkItem
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    EE_COMMON_QUICK_ACTIONS_COMMANDS = [:q].freeze

    prepended do
      include FilterableByTestReports

      has_one :agent_plan, class_name: 'WorkItems::AgentPlan', inverse_of: :work_item, autosave: true
      has_one :progress, class_name: 'WorkItems::Progress', foreign_key: 'issue_id', inverse_of: :work_item
      has_one :color, class_name: 'WorkItems::Color', foreign_key: 'issue_id', inverse_of: :work_item

      has_many :decisions, class_name: 'WorkItems::Decision', inverse_of: :work_item

      has_many :duo_workflow_links,
        class_name: '::Ai::DuoWorkflows::WorkflowWorkItem',
        foreign_key: :work_item_id,
        inverse_of: :work_item
      has_many :linked_duo_workflows,
        through: :duo_workflow_links,
        source: :workflow,
        disable_joins: true

      has_many :text_field_values, class_name: 'WorkItems::TextFieldValue', inverse_of: :work_item
      has_many :number_field_values, class_name: 'WorkItems::NumberFieldValue', inverse_of: :work_item
      has_many :date_field_values, class_name: 'WorkItems::DateFieldValue', inverse_of: :work_item
      has_many :select_field_values, class_name: 'WorkItems::SelectFieldValue', inverse_of: :work_item

      delegate :reminder_frequency, to: :progress, allow_nil: true

      scope :with_reminder_frequency, ->(frequency) {
                                        joins(:progress).where(work_item_progresses: { reminder_frequency: frequency })
                                      }
      scope :without_parent, -> {
                               where("NOT EXISTS (SELECT FROM work_item_parent_links WHERE work_item_id = issues.id)")
                             }
      scope :with_assignees, -> { joins(:issue_assignees).includes(:assignees) }
      scope :with_descendents_of, ->(ids) {
                                    joins(:work_item_parent).where(work_item_parent_links: { work_item_parent_id: ids })
                                  }
      scope :with_previous_reminder_sent_before, ->(datetime) do
        left_joins(:progress).where(
          "work_item_progresses.last_reminder_sent_at IS NULL
          OR work_item_progresses.last_reminder_sent_at <= ?",
          datetime
        )
      end
      scope :grouped_by_work_item, -> { group(:id) }
      scope :iid_after, ->(iid) { where(arel_table[:iid].gt(iid)) }

      scope :preload_indexing_data, -> do
        preloaded_data = includes(
          :dates_source,
          :author,
          :sync_object,
          :assignees,
          :namespace,
          :milestone,
          :labels,
          project: [
            :project_feature, { namespace: %i[namespace_settings namespace_settings_with_ancestors_inherited_settings] }
          ]
        )

        ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(preloaded_data.map(&:namespace)).execute

        preloaded_data
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      def with_api_entity_associations
        super.preload(:sync_object)
      end

      override :inc_relations_for_permission_check
      def inc_relations_for_permission_check
        super.includes(:synced_epic)
      end

      override :work_item_children_keyset_order
      def work_item_children_keyset_order(work_item)
        return super unless work_item.epic_work_item? && !work_item.namespace.licensed_feature_available?(:subepics)

        epic_type_id = ::WorkItems::TypesFramework::Provider.new(work_item.namespace).find_by_base_type(:epic).id
        keyset_order = ::WorkItem.work_item_children_keyset_order_config

        keyset_order.apply_cursor_conditions(
          joins(:parent_link).where.not(work_item_type_id: epic_type_id)
        ).reorder(keyset_order)
      end

      override :available_features_for_issue_types
      def available_features_for_issue_types
        super.tap do |available_features|
          available_features[:move_and_clone] += %w[epic]
        end
      end
      strong_memoize_attr :available_features_for_issue_types

      override :ordered_linked_items
      def ordered_linked_items(select_query, ids: [], link_type: nil, preload: nil)
        case link_type
        when ::WorkItems::RelatedWorkItemLink::TYPE_BLOCKS
          blocking_work_items(select_query, ids, preload)
        when ::WorkItems::RelatedWorkItemLink::TYPE_IS_BLOCKED_BY
          blocking_work_items(select_query, ids, preload, inverse_direction: true)
        else
          super
        end
      end

      def blocking_work_items(select_query, ids, preload, inverse_direction: false)
        link_class = ::WorkItems::RelatedWorkItemLink
        columns = %w[target_id source_id]
        columns.reverse! if inverse_direction

        select_query
          .joins("INNER JOIN issue_links ON issue_links.#{columns[0]} = issues.id")
          .where(issue_links: { columns[1] => ids, link_type: link_class.link_types[link_class::TYPE_BLOCKS] })
          .preload(preload)
          .reorder(linked_items_keyset_order)
          .references(:issue_links)
      end
    end

    def average_progress_of_children
      children = work_item_children
      child_count = children.count
      return 0 unless child_count > 0

      (::WorkItems::Progress.where(work_item: children).sum(:progress).to_i / child_count).to_i
    end

    # Whether a user enabled AI planning for the work item. This marks a Software Factory work item.
    #
    # @return [Boolean] false when the work item has no agent plan
    def ai_planning_enabled?
      agent_plan&.ai_planning_enabled || false
    end

    override :skip_metrics?
    def skip_metrics?
      super || group_epic_work_item?
    end

    override :use_elasticsearch?
    def use_elasticsearch?
      return project.use_elasticsearch? unless project.nil?

      namespace.use_elasticsearch?
    end

    override :supported_quick_action_commands
    def supported_quick_action_commands
      super + EE_COMMON_QUICK_ACTIONS_COMMANDS
    end

    override :supports_parent?
    def supports_parent?
      return false if (work_item_type.issue? || work_item_type.ticket?) && !licensed_feature_available?(:epics)
      return false if work_item_type.epic? && !licensed_feature_available?(:subepics)

      hierarchy_supports_parent?
    end

    override :custom_notification_target_name
    def custom_notification_target_name
      # Keep epic here because we have a dedicated `new_epic` category.
      # Notifications will be sent for `new_issue` and `new_epic` categories.
      return 'epic' if work_item_type.epic?

      # Everything else is `work_item`
      super
    end

    private

    override :allowed_work_item_type_change
    def allowed_work_item_type_change
      super

      return unless previous_type_was_epic?
      return unless synced_epic.present?

      errors.add(
        :work_item_type_id,
        format(
          _('cannot be changed to %{new_type} when the work item is a legacy epic synced work item'),
          new_type: work_item_type.name.downcase
        )
      )
    end

    def previous_type_was_epic?
      provider = ::WorkItems::TypesFramework::Provider.new(namespace)
      changes["work_item_type_id"].first == provider.find_by_base_type(:epic).id
    end

    override :validate_due_date?
    def validate_due_date?
      return false if epic_work_item?

      super
    end
  end
end
