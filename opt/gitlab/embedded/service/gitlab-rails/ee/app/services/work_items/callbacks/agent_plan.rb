# frozen_string_literal: true

module WorkItems
  module Callbacks
    class AgentPlan < Base
      ALLOWED_PARAMS = %i[content readiness_score readiness_score_feedback].freeze

      def before_create
        handle_agent_plan_change unless excluded_in_new_type?
      end

      def before_update
        if excluded_in_new_type?
          if work_item.agent_plan.present?
            work_item.agent_plan.destroy!
            @agent_plan_event = ::Gitlab::WorkItems::Instrumentation::EventActions::AGENT_PLAN_DESTROY
          end

          return
        end

        handle_agent_plan_change
      end

      def after_save_commit
        return unless @agent_plan_event

        ::Gitlab::WorkItems::Instrumentation::TrackingService.new(
          work_item: work_item,
          current_user: current_user,
          event: @agent_plan_event,
          extra_properties: ::Gitlab::WorkItems::Instrumentation::TrackingService.plan_event_properties(work_item)
        ).execute

        create_workplan_system_note
      end

      private

      def create_workplan_system_note
        change = workplan_note_change
        ::SystemNoteService.change_workplan_note(work_item, current_user, change) if change
      end

      # Clearing the content is how the UI deletes a plan. A destroy only happens on a type change
      # to one without the widget, where the note would be hidden from everyone.
      def workplan_note_change
        event_actions = ::Gitlab::WorkItems::Instrumentation::EventActions
        content_present = params[:content].present?

        case @agent_plan_event
        when event_actions::AGENT_PLAN_CREATE
          :added if content_present
        when event_actions::AGENT_PLAN_UPDATE
          content_present ? :updated : :removed
        end
      end

      def handle_agent_plan_change
        return unless agent_plan_change_requested?
        return unless has_permission?(:update_work_item)

        validate_readiness_score_flag!
        validate_readiness_score_feedback_flag!

        agent_plan = work_item.agent_plan || work_item.build_agent_plan

        apply_content(agent_plan) if params.key?(:content)
        agent_plan.readiness_score = params[:readiness_score] if params.key?(:readiness_score)

        if params.key?(:readiness_score_feedback)
          agent_plan.readiness_score_feedback = params[:readiness_score_feedback]
        end

        agent_plan.ai_planning_enabled = true if enable_ai_planning?(agent_plan)

        raise_error(agent_plan.errors.full_messages.join(', ')) unless agent_plan.valid?
      end

      def apply_content(agent_plan)
        # Use content presence rather than row persistence: a score-only call can
        # persist a row with blank content, so persisted? is no longer a reliable
        # proxy for "the plan did not exist yet".
        had_content = agent_plan.content.present?
        content_changed = agent_plan.content != params[:content]
        agent_plan.content = params[:content]
        discard_readiness_score(agent_plan) if content_changed

        @agent_plan_event = if content_changed && !had_content
                              ::Gitlab::WorkItems::Instrumentation::EventActions::AGENT_PLAN_CREATE
                            elsif content_changed
                              ::Gitlab::WorkItems::Instrumentation::EventActions::AGENT_PLAN_UPDATE
                            end
      end

      # A score describes the content it was computed from. Score params in the same call are
      # applied after this and win.
      def discard_readiness_score(agent_plan)
        agent_plan.readiness_score = nil
        agent_plan.readiness_score_feedback = nil
      end

      def agent_plan_change_requested?
        params.key?(:content) || params.key?(:readiness_score) ||
          params.key?(:readiness_score_feedback) || ai_planning_requested?
      end

      def validate_readiness_score_flag!
        return unless params.key?(:readiness_score)
        return if workplan_enabled?

        raise_error(
          s_('WorkItems|The readiness_score field requires the workplan feature flag to be enabled.')
        )
      end

      def validate_readiness_score_feedback_flag!
        return unless params.key?(:readiness_score_feedback)
        return if workplan_enabled?

        raise_error(
          s_('WorkItems|The readiness_score_feedback field requires the workplan feature flag to be enabled.')
        )
      end

      # Gated by the same flag as the read path; a score set while disabled could not be read back.
      def workplan_enabled?
        Feature.enabled?(:workplan, work_item.namespace.root_ancestor)
      end

      # The widget is hidden while this flag is false, so anything worth rendering - plan content
      # or a readiness score - has to turn it on, whatever wrote it. Clearing the content does not
      # turn it off: the flag is a one-way opt-in.
      def enable_ai_planning?(agent_plan)
        agent_plan.content.present? || agent_plan.readiness_score.present? || ai_planning_requested?
      end

      def ai_planning_requested?
        params[:ai_planning_enabled] == true &&
          work_item.new_record? &&
          Feature.enabled?(:workplan, work_item.namespace&.root_ancestor)
      end
    end
  end
end
