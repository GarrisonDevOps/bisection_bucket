# frozen_string_literal: true

module EE
  module BulkImports
    module Projects
      module Pipelines
        module IssuesPipeline
          include ::BulkImports::EpicObjectCreator

          def load(context, data)
            issue, original_users_map = data

            return unless issue

            # The epic behind `epic_issue` is persisted by EpicObjectCreator during transform, so
            # `super` pushes references for it. Add its work item before that happens.
            copy_epic_user_references_to_work_items(original_users_map)

            if issue.epic_issue.present?
              epic_from_association = issue.epic_issue.epic
              relative_position = issue.epic_issue.relative_position
              issue.epic_issue = nil
              super

              handle_issue_with_epic_association(issue, epic_from_association, relative_position)
            else
              super
            end
          end
        end
      end
    end
  end
end
