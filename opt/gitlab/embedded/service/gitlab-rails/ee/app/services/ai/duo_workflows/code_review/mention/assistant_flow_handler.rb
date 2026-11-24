# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      module Mention
        class AssistantFlowHandler < BaseHandler
          def execute
            code_review_flow = ::Ai::Catalog::FoundationalFlow.code_review_v1
            catalog_item = code_review_flow.catalog_item
            return unless catalog_item

            unless flow_enabled_for_project?(catalog_item)
              create_note_on(::Gitlab::Duo::CodeReview::Messages.foundational_flow_not_enabled_error)
              return
            end

            sa_result = ::Ai::Catalog::ItemConsumers::ResolveServiceAccountService.new(
              container: note.project.root_namespace,
              item: catalog_item
            ).execute

            unless sa_result.success?
              create_note_on(::Gitlab::Duo::CodeReview::Messages.missing_service_account_error)
              return
            end

            adapter = ::Ai::Messaging::Adapters::GitlabDuoNote.for_note(
              note, note_author_id: duo_code_review_bot.id
            )
            adapter.trigger(build_trigger_bundle(code_review_flow, sa_result.payload[:service_account]))
          end

          private

          def build_trigger_bundle(code_review_flow, service_account)
            ::Ai::Messaging::Adapters::Base::TriggerBundle.new(
              current_user: note.author,
              service_account: service_account,
              flow_reference: code_review_flow.foundational_flow_reference,
              flow_config_id: ::Ai::Messaging::Adapters::GitlabDuoNote::FLOW_CONFIG_ID,
              flow_config_schema_version: ::Ai::Messaging::Adapters::GitlabDuoNote::FLOW_CONFIG_SCHEMA_VERSION,
              flow_version: ::Ai::Messaging::Adapters::GitlabDuoNote::FLOW_VERSION,
              project: note.project,
              goal: build_goal,
              resource: note.noteable,
              source_branch: source_branch,
              source_type: :flow_trigger
            )
          end

          def source_branch
            note.noteable.source_branch if note.noteable.is_a?(MergeRequest)
          end

          def flow_enabled_for_project?(catalog_item)
            note.project.duo_foundational_flows_enabled &&
              note.project.enabled_flow_catalog_item_ids.include?(catalog_item.id)
          end

          # nil only when even the newest message cannot fit the limit.
          def build_goal
            source_context = build_source_context(::Gitlab::UrlBuilder.build(note.noteable))

            goal, = build_conversation_context.render_within(
              ::Ai::DuoWorkflows::Workflow::GOAL_MAX_LENGTH,
              on_overflow: method(:log_goal_overflow)
            ) do |conversation|
              <<~GOAL.strip
                <gitlab_context>
                #{source_context}
                </gitlab_context>

                <conversation>
                #{conversation}
                </conversation>
              GOAL
            end

            goal
          end

          def build_conversation_context
            messages = ::Gitlab::Duo::CodeReview::Mention::ConversationThread.new(note).messages

            ::Ai::Messaging::Conversation.new(messages: messages, marker: method(:omitted_marker))
          end

          def omitted_marker(count)
            return if count == 0

            "<!-- #{count} earlier #{'message'.pluralize(count)} omitted due to length -->"
          end

          def log_goal_overflow(goal_length, _overhead)
            ::Gitlab::AppLogger.error(
              message: 'Duo Code Review assistant-flow goal exceeded the limit after rendering',
              goal_length: goal_length,
              note_id: note.id
            )
          end

          def build_source_context(resource_url)
            resource_label = note.noteable.is_a?(MergeRequest) ? 'Merge request' : 'Issue'
            parts = []
            parts << "#{resource_label}: #{resource_url}"
            parts << "Project: #{note.project.full_path} (ID: #{note.project_id})"

            if note.noteable.is_a?(MergeRequest)
              mr = note.noteable
              parts << "Source branch: #{CGI.escapeHTML(mr.source_branch.to_s)}"
              parts << "Target branch: #{CGI.escapeHTML(mr.target_branch.to_s)}"
              head_sha = mr.diff_head_sha
              parts << "Current MR head SHA: #{head_sha}" if head_sha.present?
            end

            if note.diff_note?
              parts << "File: #{CGI.escapeHTML(note.latest_diff_file_path.to_s)}"
              parts << original_comment_anchor
              parts << "Diff:\n#{CGI.escapeHTML(note.raw_truncated_diff_lines.to_s)}"
            end

            parts.compact.join("\n")
          end

          def original_comment_anchor
            position = note.original_position
            return unless position&.on_text?

            sha, path, line = if position.new_line
                                [position.head_sha, position.new_path, position.new_line]
                              else
                                [position.base_sha, position.old_path, position.old_line]
                              end

            return unless sha.present? && path.present? && line.present?

            "Original comment anchored at commit #{sha}, #{path} line #{line}"
          end
        end
      end
    end
  end
end
