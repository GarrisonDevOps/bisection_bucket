# frozen_string_literal: true

module Ai
  module FlowTriggers
    class CreateNoteService
      include ::Ai::Catalog::Loggable
      include ::Ai::DuoWorkflows::Concerns::LinkArtifact

      attr_reader :project, :resource, :author, :discussion

      def initialize(project:, resource:, author:, discussion: nil)
        @project = project
        @resource = resource
        @author = author
        @discussion = discussion
      end

      def execute(params)
        note = create_note

        unless note.persisted?
          ai_catalog_logger.error(
            message: 'Failed to create processing note',
            noteable_type: resource.class.name,
            noteable_id: resource.id,
            errors: note.errors.full_messages.join(', ')
          )
        end

        response, workflow = yield(params.merge(discussion_id: note.discussion_id))

        if response.success?
          mark_started(note, workflow)
        else
          mark_failed(note, response.message)
        end

        response
      end

      def create_note
        note_body = s_('AiFlowTriggers|🔄 Processing the request...')

        # A trigger fired by another flow's API call inherits that flow's id through
        # the Sidekiq context, which would link this note to the wrong session.
        ::Gitlab::ApplicationContext.with_context(duo_workflow_id: nil) do
          ::Notes::CreateService.new(
            project,
            author,
            note: note_body,
            noteable: resource,
            in_reply_to_discussion_id: discussion&.id
          ).execute
        end
      end

      def mark_started(note, workflow)
        return unless note.persisted?

        link_artifact(workflow, note, link_type: :created)

        link_start = format('<a href="%{url}" target="_blank" rel="noopener noreferrer">'.html_safe,
          url: "#{Gitlab::Routing.url_helpers.project_automate_agent_sessions_url(project)}/#{workflow.id}")
        # Defense-in-depth: names are sanitized upstream but escape here as well
        updated_message = format(s_(
          "AiFlowTriggers|✅ %{flow_name} has started. You can view progress %{link_start}here%{link_end}."
        ), link_start: link_start, link_end: '</a>'.html_safe, flow_name: html_escape(author.name))

        return if note.update(note: updated_message)

        log_note_update_failure(note)
      end

      def mark_failed(note, error_message)
        return unless note.persisted?

        sanitized_error = ERB::Util.html_escape(Array(error_message).join(', ')).truncate(200)
        updated_message = format(s_("AiFlowTriggers|❌ Could not start processing due to this error: %{error}"),
          error: sanitized_error)

        return if note.update(note: updated_message)

        log_note_update_failure(note)
      end

      private

      def log_note_update_failure(note)
        ai_catalog_logger.error(
          message: 'Failed to update processing note',
          note_id: note.id,
          errors: note.errors.full_messages.join(', ')
        )
      end
    end
  end
end
