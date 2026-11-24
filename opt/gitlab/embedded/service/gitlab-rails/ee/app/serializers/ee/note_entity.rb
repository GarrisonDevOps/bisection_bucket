# frozen_string_literal: true

module EE
  module NoteEntity
    extend ActiveSupport::Concern

    prepended do
      include ::Gitlab::Utils::StrongMemoize

      with_options if: ->(note, _) { !note.system? } do
        expose :duo_session_id_triggered do |_note|
          triggered_duo_workflow&.to_global_id
        end

        expose :duo_session_agent_name do |_note|
          workflow = triggered_duo_workflow
          next unless workflow

          ::Ai::DuoWorkflows::WorkflowPresenter.new(workflow).agent_name
        end

        expose :duo_session_status do |_note|
          triggered_duo_workflow&.status_name
        end
      end

      expose :duo_session_id, if: ->(_note, _) { authorized_duo_session_workflow.present? } do |_note|
        authorized_duo_session_workflow.id
      end

      expose :agent_presence,
        using: ::Ai::DuoWorkflows::AgentPresenceEntity,
        if: ->(note, _) { !note.system? && agent_presence_enabled? } do |_note|
        workflow = agent_presence_workflow
        ::Ai::DuoWorkflows::AgentPresencePresenter.new(workflow) if workflow
      end

      expose :duo_session_url, if: ->(note, _) { !note.system? } do |note|
        note.duo_metadata&.workflow&.web_url
      end

      expose :duo_code_review_finding,
        if: ->(note, _) { note.for_merge_request? && note.duo_code_review_finding.present? } do |note|
        note.duo_code_review_finding.slice(:severity, :category, :depth)
      end

      # The review summary is the only non-diff note a review links, so it lists the review's findings.
      expose :duo_code_review_finding_note_ids, if: ->(*) { duo_code_review_finding_note_ids.present? }

      # Read from the workflow, not the findings, so a review that posts none still shows its depth.
      expose :duo_code_review_depth, if: ->(*) { duo_code_review_depth.present? }

      # The notes frontend routes on the presence of this field (gated on the
      # duo_mention_started action) to render the styled Duo note, and reads its
      # value to drive the progress spinner -- so expose status_name, not the raw
      # integer enum.
      #
      # duo_session_agent_name is also exposed here so that DuoCodeReviewSystemNote
      # can render the NoteSessionBar to open the session panel and display the agent
      # name. duo_session_id is covered by the authorized_duo_session_workflow expose above.
      with_options if: ->(note, _) { note.system? && note.system_note_metadata&.action == 'duo_mention_started' } do
        expose :duo_session_status do |_note|
          duo_mention_workflow&.status_name
        end

        expose :duo_session_agent_name do |_note|
          workflow = duo_mention_workflow
          next unless workflow

          ::Ai::DuoWorkflows::WorkflowPresenter.new(workflow).agent_name
        end
      end

      with_options if: ->(note, _) { note.system? && note.resource_parent.feature_available?(:description_diffs) } do
        expose :description_version_id

        expose :description_diff_path, if: ->(_) { description_version_id } do |note|
          description_diff_path(note.noteable, description_version_id)
        end

        expose :delete_description_version_path, if: ->(_) { description_version_id } do |note|
          delete_description_version_path(note.noteable, description_version_id)
        end

        expose :can_delete_description_version do |note|
          rule = "admin_#{object.noteable.class.to_ability_name}"

          Ability.allowed?(current_user, rule, object.noteable.resource_parent)
        end

        expose :description_version_deleted
      end

      private

      def duo_mention_workflow
        readable_duo_workflow(object.duo_metadata&.workflow)
      end
      strong_memoize_attr :duo_mention_workflow

      def triggered_duo_workflow
        readable_duo_workflow(object.duo_workflow_links.find(&:link_type_triggered?)&.workflow)
      end
      strong_memoize_attr :triggered_duo_workflow

      def authorized_duo_session_workflow
        readable_duo_workflow(object.duo_metadata&.workflow || created_session_workflow)
      end
      strong_memoize_attr :authorized_duo_session_workflow

      # Code review links every published comment to its session, so the per-comment
      # session link stays behind the flag until the actor line replaces the button.
      # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260150#note_4007358435
      def created_session_workflow
        workflow = object.duo_created_workflow_link&.workflow
        return workflow unless workflow && code_review_session?(workflow)

        workflow if ::Feature.enabled?(:agent_presence_consolidation, object.resource_parent.root_ancestor)
      end

      # A @GitLabDuo conversation shares the code_review/v1 definition; only the
      # automated review has no messaging adapter.
      def code_review_session?(workflow)
        workflow.workflow_definition == ::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference &&
          workflow.messaging_callback_adapter.nil?
      end

      # Unlike authorized_duo_session_workflow, not gated on read_duo_workflow: the entity reports that.
      def agent_presence_workflow
        object.duo_metadata&.workflow || object.duo_created_workflow_link&.workflow
      end

      # Deliberately not Note#resource_parent: that goes through #noteable, which hits Gitaly for commit notes.
      def agent_presence_enabled?
        actor = (object.project || object.namespace)&.root_ancestor

        actor.present? && ::Feature.enabled?(:agent_presence_consolidation, actor)
      end

      def duo_code_review_finding_note_ids
        return if object.diff_note? || !object.for_merge_request?

        workflow = object.duo_created_workflow_link&.workflow
        findings = workflow&.code_review_findings
        return if findings.blank?
        return unless object.id == duo_code_review_summary_note_id(workflow, findings)

        findings.map { |finding| finding.note_id.to_s }
      end
      strong_memoize_attr :duo_code_review_finding_note_ids

      def duo_code_review_depth
        return if object.diff_note? || !object.for_merge_request?

        workflow = object.duo_created_workflow_link&.workflow
        return unless workflow

        ::Gitlab::Duo::CodeReview.depth_for(workflow)&.to_s
      end
      strong_memoize_attr :duo_code_review_depth

      # Both summary paths post the summary as the review's last non-diff note before its findings are stored.
      # That rules out an error note left by a failed attempt that a retry completed (earlier), and an error
      # note posted after the findings were stored (later).
      def duo_code_review_summary_note_id(workflow, findings)
        stored_at = findings.map(&:created_at).min

        workflow.created_note_links.filter_map(&:note)
          .select { |note| !note.diff_note? && note.created_at <= stored_at }
          .max_by { |note| [note.created_at, note.id] }&.id
      end

      def readable_duo_workflow(workflow)
        workflow if workflow && can?(current_user, :read_duo_workflow, workflow)
      end

      def description_version_id
        object.system_note_metadata&.description_version_id
      end

      def description_version_deleted
        object.system_note_metadata&.description_version&.deleted?
      end
    end
  end
end
