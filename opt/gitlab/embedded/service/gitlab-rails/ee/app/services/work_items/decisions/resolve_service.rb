# frozen_string_literal: true

module WorkItems
  module Decisions
    class ResolveService
      def initialize(decision:, current_user:, params: {})
        @decision = decision
        @work_item = decision.work_item
        @current_user = current_user
        @params = params
      end

      def execute
        return ServiceResponse.error(message: _('Operation not allowed')) unless allowed?

        response = ApplicationRecord.transaction do
          decision.lock!
          # lock! reloads the decision and drops its cached work_item; reattach it to skip a re-query
          decision.association(:work_item).target = work_item

          error = validate_resolution
          next ServiceResponse.error(message: error) if error

          resolve_decision!
          ServiceResponse.success(payload: { decision: decision })
        end
        return response if response.error?

        track_event

        SystemNoteService.decision_recorded(decision, current_user)
        publish_resolved_event

        response
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages.to_sentence)
      end

      private

      attr_reader :decision, :work_item, :current_user, :params

      def validate_resolution
        return _('Decision is already resolved') if decision.resolved_at
        return _("Selected option content can't be blank") if writing_in? && selected_option_content.blank?

        if writing_in? && selected_option_ids.any?
          return _('Selected options and selected option content cannot be provided together')
        end

        return _('Note cannot resolve this decision') unless valid_resolving_note?
        return _('Selected options must belong to the decision') unless valid_selected_options?

        _('Resolution rationale is required when rejecting all options') if rationale_missing_for_rejection?
      end

      def valid_selected_options?
        selected_options.size == selected_option_ids.uniq.size
      end

      def rationale_missing_for_rejection?
        rejecting_all_options? && params[:resolution_rationale].blank?
      end

      # get_widget covers type registration, ai_workflows licensing, and the
      # decision_log feature flag
      def allowed?
        Ability.allowed?(current_user, :update_work_item, work_item) && work_item.get_widget(:decision_log).present?
      end

      def resolving_note
        params[:resolving_note]
      end

      def valid_resolving_note?
        return true if resolving_note.nil?

        Ability.allowed?(current_user, :read_note, resolving_note) && decision.resolvable_by_note?(resolving_note)
      end

      def resolve_decision!
        decision.select_options!(selected_option_ids)
        decision.write_in_option!(selected_option_content) if writing_in?

        decision.update!(
          resolved_at: Time.current,
          resolved_by: current_user,
          resolution_rationale: params[:resolution_rationale],
          resolving_note: resolving_note
        )
      end

      def track_event
        ::Gitlab::WorkItems::Instrumentation::TrackingService.track_decision_event(
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::DECISION_RESOLVE,
          decision: decision,
          current_user: current_user,
          extra_properties: { resolution_type: resolution_type, value: selected_count }
        )
      end

      def resolution_type
        return 'write_in' if writing_in?
        return 'option_pick' if selected_option_ids.any?
        return 'skipped' if decision.workflow_id

        decision.options.exists? ? 'reject_all' : 'no_options'
      end

      def selected_count
        writing_in? ? 1 : selected_option_ids.uniq.size
      end

      # Only Duo questions update the description, and only when an answer was given
      def publish_resolved_event
        return unless decision.workflow_id
        return unless decision.options.any?(&:selected)

        ::Gitlab::EventStore.publish(
          ::WorkItems::DecisionResolvedEvent.build(decision: decision, current_user: current_user)
        )
      end

      def selected_option_ids
        Array(params[:selected_option_ids])
      end

      def selected_option_content
        params[:selected_option_content]
      end

      def writing_in?
        !selected_option_content.nil?
      end

      def rejecting_all_options?
        selected_options.empty? && !writing_in? && decision.options.exists?
      end

      def selected_options
        @selected_options ||= decision.options.id_in(selected_option_ids)
      end
    end
  end
end
