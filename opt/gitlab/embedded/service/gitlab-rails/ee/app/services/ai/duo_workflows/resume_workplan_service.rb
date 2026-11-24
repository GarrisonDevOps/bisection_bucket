# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Triggered by the user, so unanswered questions do not block the resume -
    # whatever has been answered is what the flow gets.
    class ResumeWorkplanService
      include ::Gitlab::Utils::StrongMemoize

      PROJECT_REQUIRED_ERROR = 'Workplan generation is only available for project work items'
      FEATURE_DISABLED_ERROR = 'Async workplan generation is not enabled for this project'
      NO_WORKFLOW_ERROR = 'No workplan generation to resume for this work item'
      NOT_RESUMABLE_ERROR = 'Workplan generation is not awaiting input, or its previous run has not finished'
      EXECUTE_DENIED_ERROR = 'You are not allowed to run Duo Agent Platform flows in this project'
      OWNER_EXECUTE_DENIED_ERROR = 'The user who started this workplan generation is no longer allowed to run ' \
        'Duo Agent Platform flows in this project'
      RESUME_IN_PROGRESS_ERROR = 'A workplan resume is already in progress for this work item'

      # Exists so an unanswered resume sends an explicit "carry on" instead of
      # an empty goal the flow can't interpret.
      NO_REPLIES_MESSAGE = 'No answers were provided. Continue with your best assumptions.'

      # Must match the gate name in ai-assist's workplan/1.0.0.yml flow config.
      CONTEXT_GATE = 'context_gate'

      def initialize(work_item:, current_user:)
        @work_item = work_item
        @current_user = current_user
      end

      def execute
        return error(PROJECT_REQUIRED_ERROR, :project_required) unless project
        return error(FEATURE_DISABLED_ERROR, :feature_disabled) unless feature_enabled?
        return error(NO_WORKFLOW_ERROR, :not_found) unless workflow
        return error(EXECUTE_DENIED_ERROR, :forbidden) unless can_resume?
        return error(OWNER_EXECUTE_DENIED_ERROR, :owner_forbidden) unless owner_can_execute?
        return error(NOT_RESUMABLE_ERROR, :not_resumable) unless input_resumable?

        resume
      end

      private

      attr_reader :work_item, :current_user

      # Whoever may update the work item may resume it, matching
      # GenerateWorkplan. `resume_duo_workflow` is deliberately not used - it
      # additionally requires the resuming user to be the flow owner, which
      # would lock out everyone else on the work item.
      def can_resume?
        Ability.allowed?(current_user, :update_work_item, work_item) && project.duo_remote_flows_enabled
      end

      def owner_can_execute?
        Ability.allowed?(workflow.user, :execute_duo_workflow_in_ci, workflow)
      end

      # A Workhorse session stays `input_required` until its turn starts, so its
      # claim is held until the workflow resumes. A CI session is held back by its
      # unfinished pipeline instead.
      def resume
        claim = ::Ai::DuoWorkflows::TurnClaim.new(workflow.id)
        return error(RESUME_IN_PROGRESS_ERROR, :resume_in_progress) unless claim.obtain

        begin
          reload_workflow_on_primary
          return error(NOT_RESUMABLE_ERROR, :not_resumable) unless input_resumable?

          workhorse = workflow.last_runtime == :workhorse
          result = ::Ai::DuoWorkflows::ExecuteRunService.new(
            workflow,
            event: { type: 'input', text: goal_message },
            source_branch: project.default_branch
          ).execute

          return result if result.error?

          track_resume
          ServiceResponse.success(payload: { workflow: workflow })
        ensure
          claim.release unless workhorse && result&.success?
        end
      end

      # The previous turn releases the claim when it resumes, which can be after
      # a replica last saw the session awaiting input.
      def reload_workflow_on_primary
        ::Gitlab::Database::LoadBalancing::SessionMap
          .current(::Ai::DuoWorkflows::Workflow.load_balancer)
          .use_primary { workflow.reload } # rubocop:disable Cop/ActiveRecordAssociationReload -- the record, not an association
      end

      def project
        work_item.project
      end
      strong_memoize_attr :project

      def feature_enabled?
        ::Feature.enabled?(:workplan, project.root_ancestor)
      end

      def workflow
        workplan_workflows.order_id_desc.first
      end
      strong_memoize_attr :workflow

      def workplan_workflows
        work_item.duo_workflows
          .with_workflow_definition(::Ai::Catalog::FoundationalFlow.workplan_v1.reference)
      end

      # Drop once `resumable?` covers every runtime: https://gitlab.com/gitlab-org/gitlab/-/work_items/629005#note_4190003600
      def input_resumable?
        workflow.input_required? && (workflow.last_runtime == :workhorse || workflow.resumable?)
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end

      # A context request pauses at its own gate, and the flow researches the
      # work item again, so it gets its original goal back rather than replies.
      def goal_message
        return workflow.goal if paused_gate == CONTEXT_GATE

        reply_message
      end
      strong_memoize_attr :goal_message

      # The gate writes a request entry to the chat log when it pauses, so the
      # latest one names the gate this resume answers.
      def paused_gate
        workflow.latest_ui_chat_log.reverse.find { |entry| entry['message_type'] == 'request' }&.[]('component_name')
      end
      strong_memoize_attr :paused_gate

      # Records current_user, since the flow itself stays bound to whoever started it.
      def track_resume
        tracking_service = ::Gitlab::WorkItems::Instrumentation::TrackingService

        tracking_service.new(
          work_item: work_item,
          current_user: current_user,
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::WORKPLAN_RESUME,
          extra_properties: tracking_service.plan_event_properties(work_item)
            .merge(label: resume_label, workflow_id: workflow.id)
        ).execute
      end

      def resume_label
        return 'context_request' if paused_gate == CONTEXT_GATE

        goal_message == NO_REPLIES_MESSAGE ? 'no_answers' : 'answers'
      end

      # Restates every question ever posted so no "delivered" marker is needed.
      def reply_message
        # A note without an answer-card payload is a context request or a progress comment, and a
        # reply to it is not an answer. Filtered before the per-thread pick, so a question posted
        # under a progress comment still counts.
        questions = flow_notes
          .select { |note| ::Gitlab::WorkItems::DuoQuestion.payload_hint?(note.note) }
          .uniq(&:discussion_id)
        replies = replies_by_discussion_id(questions)

        message = questions.filter_map { |note| discussion_reply_text(note, replies) }.join(' ')
        return NO_REPLIES_MESSAGE if message.blank?

        # The goal is never written to the workflow record on this path, so the
        # model's own length validation never runs. Cap it here instead, to keep
        # DUO_WORKFLOW_GOAL under Linux's MAX_ARG_STRLEN.
        message
          .truncate(::Ai::DuoWorkflows::Workflow::GOAL_MAX_LENGTH, omission: '')
          .truncate_bytes(::Ai::DuoWorkflows::Workflow::GOAL_MAX_BYTESIZE, omission: '')
      end

      # Only notes the flow wrote. `linked_notes` also covers the note that
      # triggered the flow, which would hand the agent its own prompt back as a
      # question to answer.
      #
      # Spans every workplan run on the work item: a failed or stopped run
      # leaves its questions open, and the next run does not ask them again,
      # so their answers have to travel with this resume.
      def flow_notes
        ::Note.created_by_duo_workflows(workplan_workflows).order_created_at_id_asc.to_a
      end
      strong_memoize_attr :flow_notes

      # `Note#discussion` isn't a real association - it queries per call - so
      # looping the questions would be an N+1; this does one query instead.
      #
      # Anyone can post a reply, and whether it counts toward the goal is
      # decided below in `trusted_notes`, not here. What this does exclude is
      # the flow's own notes, by the whole id set rather than just the
      # question being answered: it posts more than once per discussion, and
      # its later messages would otherwise come back to it as answers to its
      # earlier ones.
      def replies_by_discussion_id(questions)
        return {} if questions.empty?

        notes = Note.with_discussion_ids(questions.map(&:discussion_id))
          .id_not_in(flow_notes.map(&:id))
          .order_created_at_id_asc
          .to_a

        trusted_notes(notes).group_by(&:discussion_id)
      end

      # Replies from Guest and below do not count toward the goal, regardless
      # of whether their author can press resume: `update_work_item` reaches a
      # Guest who authored or is assigned the item, but the flow they'd be
      # steering runs under the owner's identity, tokens and push access - a
      # narrower boundary than who can update the work item. Batched in one
      # query rather than checked per note, which would be an N+1 across
      # distinct authors.
      def trusted_notes(notes)
        access_levels = project.team.max_member_access_for_user_ids(notes.map(&:author_id).uniq)

        notes.select do |note|
          access_levels.fetch(note.author_id, ::Gitlab::Access::NO_ACCESS) > ::Gitlab::Access::GUEST
        end
      end

      def discussion_reply_text(question_note, replies_by_discussion_id)
        replies = replies_by_discussion_id.fetch(question_note.discussion_id, [])
        return if replies.empty?

        answers = replies.map { |reply| single_line(reply.note) }.join(' ')

        "Q: #{single_line(question_text(question_note))} A: #{answers}"
      end

      # A body can be the payload alone, so fall back to the question it carries, and to the raw
      # body for the legacy marker, which carries no question.
      def question_text(note)
        ::Gitlab::WorkItems::DuoQuestion.strip_payloads(note.note).presence ||
          ::Gitlab::WorkItems::DuoQuestion.parse(note.note)&.dig(:question) ||
          note.note
      end

      # The goal rides a CI variable set with `expand: false`, and the sandbox
      # wrapper passes it by reference rather than by value, so it needs no
      # shell escaping. This only keeps the Q/A framing on one line.
      def single_line(text)
        text.to_s.split.join(' ')
      end
    end
  end
end
