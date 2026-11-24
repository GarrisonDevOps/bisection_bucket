# frozen_string_literal: true

module Mcp
  module Tools
    module WorkItems
      class UpdateWorkItemTool < BaseTool
        include SaveWorkItemCommon

        register_version VERSIONS[:v0_1_0], {
          operation_name: 'workItemUpdate',
          graphql_operation: load_graphql('work_items/update_work_item.mutation.graphql')
        }

        CREATE_ONLY_PARAMS = %i[type_name label_ids labels].freeze

        def build_variables
          ensure_single_parent_identifier!
          validate_update_params!

          input = {
            id: resolve_work_item_id,
            title: params[:title],
            confidential: params[:confidential],
            stateEvent: state_event,
            descriptionWidget: description_widget,
            assigneesWidget: assignees_widget,
            labelsWidget: labels_widget,
            milestoneWidget: milestone_widget,
            startAndDueDateWidget: start_and_due_date_widget,
            hierarchyWidget: hierarchy_widget,
            currentUserTodosWidget: current_user_todos_widget,
            healthStatusWidget: health_status_widget,
            weightWidget: weight_widget,
            statusWidget: status_widget,
            agentPlanWidget: agent_plan_widget
          }.compact

          { input: input }
        end

        private

        def validate_update_params!
          CREATE_ONLY_PARAMS.each do |param|
            next unless params.key?(param)

            raise ArgumentError, "#{param} can only be used when creating (omit work_item_iid)"
          end

          if params.key?(:description) && params.key?(:description_edits)
            raise ArgumentError, 'Provide either description or description_edits, not both'
          end

          return unless params.key?(:todo_id) && !params.key?(:todo_action)

          raise ArgumentError, 'todo_action is required when todo_id is provided'
        end

        def description_widget
          if params.key?(:description)
            validate_no_quick_actions!(params[:description], field_name: 'description')
            { description: params[:description] }
          elsif params.key?(:description_edits)
            { description: apply_description_edits }
          end
        end

        def apply_description_edits
          item = resolve_work_item
          current_description = item.description.to_s
          edits = params[:description_edits]

          raise ArgumentError, 'description_edits must be an array' unless edits.is_a?(Array)
          raise ArgumentError, 'description_edits cannot be empty' if edits.empty?

          new_description = edits.reduce(current_description) do |content, edit|
            apply_single_description_edit(content, edit)
          end

          validate_description_edits_quick_actions!(current_description, new_description)

          if new_description.length > Concerns::Constants::MARKDOWN_TEXT_MAX_LENGTH
            raise ArgumentError,
              "Description exceeds maximum length of #{Concerns::Constants::MARKDOWN_TEXT_MAX_LENGTH} characters"
          end

          new_description
        end

        def apply_single_description_edit(content, edit)
          edit_hash = edit.is_a?(Hash) ? edit.with_indifferent_access : {}
          unless edit_hash.key?(:old_str) && edit_hash.key?(:new_str)
            raise ArgumentError, 'Provide both old_str and new_str for each edit in description_edits'
          end

          old_str = edit_hash[:old_str].to_s
          new_str = edit_hash[:new_str].to_s

          raise ArgumentError, 'old_str cannot be empty in description_edits' if old_str.empty?

          occurrences = content.scan(old_str).length
          if occurrences == 0
            raise ArgumentError, "old_str was not found in description: #{old_str.truncate(60).inspect}"
          elsif occurrences > 1
            msg = [
              "old_str is ambiguous in description (#{occurrences} matches found);",
              "provide more surrounding context: #{old_str.truncate(60).inspect}"
            ].join(' ')
            raise ArgumentError, msg
          end

          content.sub(old_str) { new_str }
        end

        def validate_description_edits_quick_actions!(current_description, new_description)
          original_actions = current_description.lines.grep(Concerns::ContentValidation::QUICK_ACTION_PATTERN).map(&:strip)
          new_actions = new_description.lines.grep(Concerns::ContentValidation::QUICK_ACTION_PATTERN).map(&:strip)

          return if (new_actions - original_actions).empty?

          raise ArgumentError, 'Quick actions (commands starting with /) are not allowed in description'
        end

        def state_event
          return unless params.key?(:state)

          params[:state] == 'closed' ? 'CLOSE' : 'REOPEN'
        end

        def labels_widget
          {
            addLabelIds: combined_label_gids(:add_label_ids, :add_labels),
            removeLabelIds: combined_label_gids(:remove_label_ids, :remove_labels)
          }.compact.presence
        end

        # Clearing a weight requires an explicit null in the mutation input; the widget
        # hash itself is non-nil, so the surrounding compact keeps the inner nil intact.
        def weight_widget
          return { weight: nil } if params[:clear_weight]
          return unless params.key?(:weight)

          { weight: params[:weight] }
        end

        def current_user_todos_widget
          return unless params.key?(:todo_action)

          {
            action: params[:todo_action].to_s.upcase,
            todoId: params[:todo_id] && normalize_gid(params[:todo_id], 'Todo')
          }.compact
        end

        # Mutation authorization failures (readable but not updatable) surface as a top-level
        # GraphQL error; missing/unreadable items already raise upstream in build_variables.
        def process_result(result)
          if resource_access_denied?(result)
            return ::Mcp::Tools::Base::Response.error(
              'Work item not found: it does not exist or you do not have access to it.',
              reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
            )
          end

          super
        end
      end
    end
  end
end
