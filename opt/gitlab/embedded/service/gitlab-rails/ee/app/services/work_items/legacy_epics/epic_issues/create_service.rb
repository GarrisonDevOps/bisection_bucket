# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module EpicIssues
      class CreateService
        include ::Gitlab::Utils::StrongMemoize

        def initialize(legacy_epic, user, params)
          @legacy_epic = legacy_epic
          @user = user
          @params = params
        end

        def execute
          @existing_epic_issue_ids = EpicIssue.in_epic(legacy_epic.id)
            .for_issue(referenced_child_work_items.map(&:id)).pluck_primary_key

          parent_work_item = legacy_epic.work_item
          update_service = ::WorkItems::UpdateService.new(
            container: parent_work_item.resource_parent,
            current_user: user,
            params: {},
            widget_params: {
              hierarchy_widget: { children: referenced_child_work_items }.merge(params.slice(:skip_add_children_limits))
            }
          )

          # Issue epic assignment and project transfer are counted or bounded on their own,
          # so they ask for the parent update to skip the work item update limit.
          result = if params[:skip_work_item_update_limit]
                     update_service.execute_without_rate_limiting(parent_work_item)
                   else
                     update_service.execute(parent_work_item)
                   end

          Gitlab::WorkItems::LegacyEpics::TransformServiceResponse.new(result:)
            .transform(created_references_lambda: -> { created_references },
              error_message_lambda: -> { error_message_creator })
        end

        private

        attr_reader :legacy_epic, :user, :params

        def referenced_child_work_items
          target_issuable = params[:target_issuable]

          if params[:issuable_references].present?
            extract_references
          elsif target_issuable
            WorkItem.id_in(Array.wrap(target_issuable).map(&:id))
          else
            []
          end
        end
        strong_memoize_attr :referenced_child_work_items

        def extract_references
          issuable_references = params[:issuable_references]
          text = issuable_references.join(' ')

          extractor = Gitlab::ReferenceExtractor.new(nil, user)
          extractor.analyze(text, { group: legacy_epic.group })

          WorkItem.id_in(extractor.issues.map(&:id)) + extractor.work_items
        end

        def created_references
          EpicIssue.in_epic(legacy_epic.id)
            .id_not_in(@existing_epic_issue_ids)
            .for_issue(referenced_child_work_items.map(&:id))
        end

        def error_message_creator
          ::Gitlab::WorkItems::IssuableLinks::ErrorMessage.new(target_type: 'issue')
        end
      end
    end
  end
end
