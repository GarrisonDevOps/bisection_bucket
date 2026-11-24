# frozen_string_literal: true

module WorkItems
  module Decisions
    # Records a clarifying question posted by the workplan flow as an open decision,
    # so answering the question later only has to resolve it.
    class CreateFromDuoQuestionService
      def initialize(note:, workflow:, current_user:)
        @note = note
        @workflow = workflow
        @current_user = current_user
      end

      # @return [ServiceResponse, nil] the create response, or nil when the note isn't a question to record,
      #   including a question whose payload doesn't parse
      def execute
        return unless workplan_workflow?
        return unless flow_authored?
        return unless ::Gitlab::WorkItems::DuoQuestion.payload_hint?(note.note)
        return unless work_item&.get_widget(:decision_log)

        unless payload
          track_invalid_question
          return
        end

        response = CreateService.new(work_item: work_item, current_user: current_user, params: decision_params).execute
        track_question(response.payload[:decision]) if response.success?
        response
      end

      private

      attr_reader :note, :workflow, :current_user

      def workplan_workflow?
        workflow.workflow_definition == ::Ai::Catalog::FoundationalFlow.workplan_v1.reference
      end

      # The workflow ID comes from a client-supplied header, so also require the note to come
      # from the service account running that workflow, not a human posting a payload of their own.
      def flow_authored?
        workflow.service_account_id.present? && note.author_id == workflow.service_account_id
      end

      def payload
        @payload ||= ::Gitlab::WorkItems::DuoQuestion.parse(note.note)
      end

      def work_item
        return unless note.for_issue?

        @work_item ||= ::WorkItem.find_by_id(note.noteable_id)
      end

      def decision_params
        {
          question: title,
          description: s_('WorkItemDecisionLog|GitLab Duo raised this question during review of the work item.'),
          discussion_id: note.discussion_id,
          options: options,
          workflow: workflow
        }
      end

      # The marker form carries no question, so its title comes from the prose around it.
      def title
        question = payload[:question] || ::Gitlab::WorkItems::DuoQuestion.strip_payloads(note.note).squish

        question.truncate(WorkItems::Decision::TITLE_LENGTH_MAX)
      end

      def track_question(decision)
        ::Gitlab::WorkItems::Instrumentation::TrackingService.track_decision_event(
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::DUO_QUESTION_CREATE,
          decision: decision,
          current_user: current_user,
          extra_properties: { label: 'valid', value: offered_options_count, workflow_id: workflow.id }
        )
      end

      # What the flow wrote, before invalid options are dropped and the rest capped, to expose bad flow output.
      def offered_options_count
        closed_question? ? payload[:declared_count] : 0
      end

      # The note looks like a question but its payload does not parse, so no decision is created.
      def track_invalid_question
        tracking_service = ::Gitlab::WorkItems::Instrumentation::TrackingService

        tracking_service.new(
          work_item: work_item,
          current_user: current_user,
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::DUO_QUESTION_CREATE,
          extra_properties: tracking_service.plan_event_properties(work_item)
            .merge(label: 'invalid', workflow_id: workflow.id)
        ).execute
      end

      def options
        return [] unless closed_question?

        payload[:options].first(WorkItems::Decision::MAX_OPTIONS_PER_DECISION).map do |option|
          option.slice(:description, :recommended).merge(content: option[:label])
        end
      end

      def closed_question?
        payload[:type] == ::Gitlab::WorkItems::DuoQuestion::QUESTION_TYPE_CLOSED
      end
    end
  end
end
