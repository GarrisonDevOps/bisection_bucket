# frozen_string_literal: true

module EE
  module Notes
    module CreateService
      include ::Ai::DuoWorkflows::Concerns::LinkArtifact
      include ::Gitlab::Utils::StrongMemoize
      extend ::Gitlab::Utils::Override

      # Server-side callers can pass the flow that posts the note as params[:workflow]. Unlike the
      # client-supplied workflow header, it is not authorized against the current user.
      override :execute
      def execute(...)
        caller_duo_workflow

        super(...)
      end

      private

      # NewNoteWorker resolves a flow-to-flow mention through this link. AfterCommitQueue runs callbacks
      # last in, first out, so registering after super writes the link before the worker is queued.
      override :after_commit
      def after_commit(note)
        super

        workflow = caller_duo_workflow || creating_duo_workflow
        return unless workflow

        link = -> { link_artifact(workflow, note, link_type: :created) }
        note.run_after_commit { link.call }
      end

      override :when_saved
      def when_saved(note, **)
        super

        workflow = creating_duo_workflow
        return unless workflow

        create_duo_question_decision(note, workflow)
      end

      # Taken out of params before Notes::BuildService passes them to Note.new
      def caller_duo_workflow
        params.delete(:workflow)
      end
      strong_memoize_attr :caller_duo_workflow

      # The header is client-supplied, so authorize the current user against the workflow
      def creating_duo_workflow
        workflow_id = ::Gitlab::ApplicationContext.current_context_attribute(:duo_workflow_id)
        return unless workflow_id

        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless workflow && ::Ability.allowed?(current_user, :update_duo_workflow, workflow)
        return unless acting_as_service_account?(workflow)

        workflow
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow_id)
        nil
      end
      strong_memoize_attr :creating_duo_workflow

      def acting_as_service_account?(workflow)
        return true unless workflow.service_account_id

        ::Gitlab::Auth::Identity.resolve_composite_identity_actor(current_user).id == workflow.service_account_id
      end

      def create_duo_question_decision(note, workflow)
        ::WorkItems::Decisions::CreateFromDuoQuestionService.new(
          note: note,
          workflow: workflow,
          current_user: current_user
        ).execute
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id, note_id: note.id)
      end

      override :track_event
      def track_event(note, user)
        track_note_creation_usage_for_epics(user, note) if note.for_epic?

        super(note, user)
      end

      def track_note_creation_usage_for_epics(user, note)
        ::Gitlab::UsageDataCounters::EpicActivityUniqueCounter.track_epic_note_created_action(
          author: user,
          namespace: note.noteable.group
        )
      end
    end
  end
end
