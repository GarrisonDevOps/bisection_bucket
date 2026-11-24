# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class CreateCommentsService
        include ::Gitlab::Utils::StrongMemoize
        include ::Ai::DuoWorkflows::CodeReview::Observability
        include ::Ai::DuoWorkflows::Concerns::LinkArtifact

        def initialize(
          user:,
          merge_request:,
          review_output:,
          progress_note:,
          workflow_id: nil
        )
          @user = user
          @merge_request = merge_request
          @review_output = review_output
          @progress_note = progress_note
          @workflow_id = workflow_id
        end

        def execute
          processed_comments = ProcessCommentsService.new(
            user: user,
            merge_request: merge_request,
            review_output: review_output,
            review_bot: review_bot
          ).execute

          metrics = processed_comments.payload[:metrics]
          message = processed_comments.message

          log_metrics(metrics) if metrics

          if processed_comments.error?
            create_todo = processed_comments.payload.fetch(:create_todo, false)
            update_progress_note(message, with_todo: create_todo)
            return error(message)
          end

          draft_notes = Array(processed_comments.payload[:draft_notes])

          if draft_notes.empty?
            update_progress_note(message, with_todo: true)
            track_review_merge_request_event('find_no_issues_duo_code_review_after_review')
          else
            publish_draft_notes(draft_notes, message, processed_comments.payload[:comments_by_draft_note])
          end

          review_state_set = approve_or_request_changes(draft_notes, processed_comments.payload)

          ServiceResponse.success
        rescue StandardError => error
          track_review_merge_request_exception(error)
          track_review_merge_request_event('encounter_duo_code_review_error_during_review')
          message = ::Gitlab::Duo::CodeReview::Messages.generic_error
          update_progress_note(message, with_todo: true)
          error(message)
        ensure
          update_review_state('reviewed') unless review_state_set
          progress_note&.destroy
        end

        private

        attr_reader :user, :merge_request, :review_output, :progress_note, :workflow_id

        def project
          merge_request.project
        end
        strong_memoize_attr :project

        def review_bot
          Users::Internal.in_organization(project.organization_id).duo_code_review_bot
        end
        strong_memoize_attr :review_bot

        def update_progress_note(note, with_todo: false)
          return unless progress_note

          TodoService.new.new_review(merge_request, review_bot) if with_todo

          created_note = ::Notes::CreateService.new(
            project,
            review_bot,
            noteable: merge_request,
            note: note,
            workflow_id: workflow&.id
          ).execute

          link_created_note(created_note)
          created_note
        end

        def decisions_enabled?
          ::Gitlab::Duo::CodeReview.decisions_settings_available?(project) && project.duo_code_review_decisions_enabled
        end

        def approve_or_request_changes(draft_notes, payload)
          return false unless decisions_enabled?
          return false unless Ability.allowed?(user, :create_note, merge_request)
          return approve_merge_request if payload[:no_issues_found]

          draft_notes.any? && request_changes
        end

        def approve_merge_request
          return false unless ::MergeRequests::ApprovalService
            .new(project: project, current_user: review_bot)
            .execute(merge_request)
            .success?

          track_review_merge_request_event(
            'approve_merge_request_duo_code_review',
            additional_properties: { property: merge_request.id.to_s }
          )
          audit_decision('duo_code_review_approved', 'GitLab Duo approved merge request')

          true
        end

        def request_changes
          return false unless update_review_state('requested_changes').to_h[:status] == :success

          audit_decision(
            'duo_code_review_changes_requested',
            'GitLab Duo requested changes on merge request',
            override_requested_changes: merge_request.override_requested_changes?
          )

          true
        end

        # The decision is already saved, so an audit failure must not fail the review.
        def audit_decision(name, message, **details)
          ::Gitlab::Audit::Auditor.audit(
            name: name,
            author: review_bot,
            scope: project,
            target: merge_request,
            message: message,
            additional_details: details
          )
        rescue StandardError => error
          track_review_merge_request_exception(error)
        end

        def update_review_state(state)
          return unless merge_request

          ::MergeRequests::UpdateReviewerStateService.new(
            project: project,
            current_user: review_bot,
            review_workflow_id: workflow&.id
          ).execute(merge_request, state)
        end

        def publish_draft_notes(draft_notes, summary, comments_by_draft_note)
          return unless Ability.allowed?(user, :create_note, merge_request)
          return if draft_notes.empty?

          DraftNote.bulk_insert_and_keep_commits!(draft_notes, batch_size: 20)

          publish_params = {}
          if progress_note && Feature.enabled?(:improved_review_email, project)
            publish_params[:summary_note] = { noteable: merge_request, note: summary, workflow_id: workflow&.id }
          else
            update_progress_note(summary)
          end

          track_review_merge_request_event(
            'post_comment_duo_code_review_on_diff',
            additional_properties: {
              value: draft_notes.size
            }
          )

          # We set `executing_user` as the user who executed the duo code
          # review action as we only want to publish duo code review bot's review
          # if the executing user is allowed to create notes on the MR.
          result = DraftNotes::PublishService
            .new(
              merge_request,
              review_bot,
              publish_params
            ).execute(executing_user: user)

          link_published_notes(result)
          store_findings(result, comments_by_draft_note)

          result
        end

        def store_findings(publish_result, comments_by_draft_note)
          return unless workflow

          StoreFindingsService.new(
            merge_request: merge_request,
            review_id: publish_result[:review_id],
            comments_by_draft_note: comments_by_draft_note,
            workflow: workflow
          ).execute
        end

        def link_published_notes(publish_result)
          return unless workflow && publish_result[:status] == :success

          review = merge_request.reviews.find_by_id(publish_result[:review_id])
          return unless review

          review.notes.each { |note| link_created_note(note) }
        end

        def link_created_note(note)
          return unless workflow && note.persisted?

          link_artifact(workflow, note, link_type: :created)
        end

        def workflow
          return unless workflow_id

          found = ::Ai::DuoWorkflows::Workflow
            .for_project(project)
            .with_workflow_definition(::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference)
            .find_by_id(workflow_id)

          found if found && Ability.allowed?(user, :update_duo_workflow, found)
        end
        strong_memoize_attr :workflow

        def log_metrics(metrics)
          return unless Feature.enabled?(:duo_code_review_response_logging, user)

          log_review_merge_request_event(
            message: "LLM response comments metrics",
            event: "review_merge_request_llm_response_comments",
            merge_request_id: merge_request.id,
            total_comments: metrics.total_comments,
            comments_with_valid_path: metrics.comments_with_valid_path,
            comments_with_valid_line: metrics.comments_with_valid_line,
            comments_with_custom_instructions: metrics.comments_with_custom_instructions,
            comments_line_matched_by_content: metrics.comments_line_matched_by_content,
            draft_notes_created: metrics.draft_notes_created,
            comments_by_severity: metrics.comments_by_severity
          )
        end
      end
    end
  end
end
