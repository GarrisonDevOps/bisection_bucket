# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    class WorkItemAsEpic
      include Gitlab::Utils::StrongMemoize

      attr_reader :work_item

      def self.epic_issue_api_preloads(relation)
        relation
          .select(
            'issues.*',
            'work_item_parent_links.id AS parent_link_id',
            'work_item_parent_links.relative_position AS parent_link_relative_position'
          )
          .includes(parent_link: [:work_item_parent, :epic_issue])
          .preload(project: [:namespace, :project_feature])
      end

      def initialize(work_item)
        @work_item = work_item
      end

      def id
        epic.id
      end

      def work_item_id
        work_item.id
      end

      def iid
        work_item.iid
      end

      def title
        work_item.title
      end

      def description
        work_item.description
      end

      def state
        work_item.state
      end

      def author
        work_item.author
      end

      def created_at
        work_item.created_at
      end

      def updated_at
        work_item.updated_at
      end

      def closed_at
        work_item.closed_at
      end

      def confidential
        work_item.confidential
      end

      def confidential?
        work_item.confidential
      end

      def lock_version
        work_item.lock_version
      end

      def imported?
        work_item.imported?
      end

      def imported_from
        work_item.imported_from
      end

      def labels
        work_item.labels
      end

      def color
        work_item.color&.color.to_s
      end

      def text_color
        work_item.color&.text_color.to_s
      end

      def group_id
        work_item.namespace_id
      end
      strong_memoize_attr :group_id

      def group
        work_item.namespace
      end
      strong_memoize_attr :group

      def start_date
        rollupable_dates_widget.start_date
      end

      def start_date_fixed
        start_date
      end

      def start_date_is_fixed?
        rollupable_dates_widget.fixed?
      end

      def start_date_from_inherited_source
        rollupable_dates_widget.start_date&.to_time
      end

      def start_date_from_milestones
        start_date_from_inherited_source
      end

      def due_date
        rollupable_dates_widget.due_date
      end

      def due_date_fixed
        due_date
      end

      def due_date_is_fixed?
        rollupable_dates_widget.fixed?
      end

      def due_date_from_inherited_source
        rollupable_dates_widget.due_date&.to_time
      end

      def due_date_from_milestones
        due_date_from_inherited_source
      end

      def parent_id
        return unless has_parent?

        parent_work_item.sync_object.id
      end

      def parent_iid
        return unless has_parent?

        parent_work_item.iid
      end

      def parent_group_id
        return unless has_parent?

        parent_work_item.namespace_id
      end

      def parent
        return unless has_parent?

        parent_work_item.sync_object
      end

      def has_parent?
        work_item.parent_link.present?
      end
      strong_memoize_attr :has_parent?

      def work_item_parent_link_id
        return unless has_parent?

        work_item.parent_link.id
      end

      def to_reference(from = nil, full: false)
        epic.to_reference(from, full: full)
      end

      def upvotes
        work_item.upvotes
      end

      def downvotes
        work_item.downvotes
      end

      def subscribed?(user)
        epic.subscribed?(user)
      end

      def web_url
        ::Gitlab::Routing.url_helpers.group_epic_url(group, epic)
      end

      def web_edit_url
        ::Gitlab::Routing.url_helpers.group_epic_path(group, epic)
      end

      def start_date_from_inherited_source_title
        epic.start_date_from_inherited_source_title
      end

      def due_date_from_inherited_source_title
        epic.due_date_from_inherited_source_title
      end

      def epic_issues
        child_issues.merge(epic_issue_order)
      end

      def find_child_issue(child_id)
        child_issues.find_by(id: child_id)
      end

      private

      def epic
        work_item.sync_object
      end
      strong_memoize_attr :epic

      def rollupable_dates_widget
        work_item.get_widget(:start_and_due_date)
      end
      strong_memoize_attr :rollupable_dates_widget

      def parent_work_item
        return unless has_parent?

        work_item.parent_link.work_item_parent
      end
      strong_memoize_attr :parent_work_item

      def child_issues
        return ::WorkItem.none unless work_item.epic_work_item?

        work_item.work_item_children
          .where(work_item_type_id: ::WorkItems::TypesFramework::Provider.new.find_by_base_type(:issue).id)
      end

      def epic_issue_order
        parent_link_table = ::WorkItems::ParentLink.arel_table

        ::WorkItems::ParentLink.reorder(
          parent_link_table[:relative_position].asc.nulls_last,
          parent_link_table[:id].asc
        )
      end
    end
  end
end
