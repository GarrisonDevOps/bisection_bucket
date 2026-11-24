# frozen_string_literal: true

module BulkImports
  module EpicObjectCreator
    extend ActiveSupport::Concern

    included do
      def save_relation_object(relation_object, relation_key, relation_definition, relation_index)
        return super unless %w[epics epic issues issue].include?(relation_key)

        if %w[issues issue].include?(relation_key)
          epic_from_association = relation_object.epic_issue&.epic
          relative_position = relation_object.epic_issue&.relative_position

          relation_object.epic_issue = nil
          super

          return handle_issue_with_epic_association(relation_object, epic_from_association, relative_position)

        end

        relation_object.relative_position = nil

        create_epic(relation_object) if relation_object.new_record?
      end

      def persist_relation(attributes)
        relation_object = super(**attributes)

        return relation_object if !relation_object || !relation_object.is_a?(::Epic) || relation_object.persisted?

        create_epic(relation_object)
      end

      private

      def create_epic(epic_object)
        # we need to handle epics slightly differently because Epics::CreateService accounts for creating the
        # respective epic work item as well as some other associations.
        created_epic = ::WorkItems::LegacyEpics::Imports::CreateFromImportedEpicService.new(
          group: epic_object.group, current_user: current_user, epic_object: epic_object
        ).execute

        mark_built_epic_as_persisted(epic_object, created_epic)

        created_epic
      end

      # The service above persists a different Epic record than the one RelationFactory built, so
      # `epic_object` stays a new record. Gitlab::ImportExport::Base::ObjectBuilder caches that
      # instance for the lifetime of the job, and every later reference to the same epic (sub-epics
      # sharing a parent, issues sharing an epic) would create it again, violating the unique index
      # on issues (namespace_id, iid). Point the built instance at the row that was persisted so
      # those references reuse it instead.
      def mark_built_epic_as_persisted(epic_object, created_epic)
        return unless created_epic&.persisted?

        epic_object.id = created_epic.id
        epic_object.reload # rubocop:disable Cop/ActiveRecordAssociationReload -- reloads the record, not an association
      end

      # With WorkItem, an issue is created alongside every epic. Both rows need a placeholder
      # reference: reassignment runs `update_all` per referenced row and WorkItems::SyncAsEpic only
      # syncs WorkItem -> Epic, so referencing the epic alone leaves the work item -- the record the
      # UI reads -- pointing at the placeholder user. Every epic in the map is covered because epics
      # built from a nested relation (a sub-epic's `parent`, an issue's `epic_issue.epic`) never
      # appear as the top-level object of a line. `keys` is snapshotted because the map is mutated
      # in the loop.
      def copy_epic_user_references_to_work_items(original_users_map)
        original_users_map.keys.grep(::Epic).each do |epic_object|
          next unless epic_object.issue_id

          original_users_map[epic_object.issue] ||= original_users_map[epic_object]
        end
      end

      def handle_issue_with_epic_association(issue, epic, relative_position)
        return issue unless epic

        epic_work_item = epic.new_record? ? create_epic(epic)&.work_item : epic.work_item
        issue_as_work_item = WorkItem.find_by_id(issue.id)

        return unless issue_as_work_item && epic_work_item

        link = create_parent_link(epic_work_item, issue_as_work_item, relative_position)
        return issue unless link

        issue
      end

      def create_parent_link(parent_work_item, child_work_item, relative_position)
        # since we are working with imported items, we have to temporarily set this attribute on the child, so that
        # the Epics::Links::CreateService knows not to perform validation related to hierarchy.

        # Importing isn't set on the child work item anymore because we persisted it separately to handle the epic issue
        # relation first. More context on the discussion around work item hierarchy permissions vs legacy epics
        # can be found here https://gitlab.com/gitlab-org/gitlab/-/issues/505855
        child_work_item.importing = true
        result = ::WorkItems::ParentLinks::CreateService.new(
          parent_work_item,
          current_user,
          { target_issuable: child_work_item, relative_position: relative_position }
        ).execute

        child_work_item.importing = nil

        return unless result[:status] == :success

        result[:created_references]&.first
      end
    end
  end
end
