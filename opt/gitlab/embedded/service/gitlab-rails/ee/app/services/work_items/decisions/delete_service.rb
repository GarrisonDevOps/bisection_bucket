# frozen_string_literal: true

module WorkItems
  module Decisions
    class DeleteService
      def initialize(decision:, current_user:)
        @decision = decision
        @work_item = decision.work_item
        @current_user = current_user
      end

      def execute
        return ServiceResponse.error(message: _('Operation not allowed')) unless allowed?

        response = ApplicationRecord.transaction do
          decision.lock!
          # lock! reloads the decision and drops its cached work_item; reattach it to skip a re-query
          decision.association(:work_item).target = work_item

          error = validate_deletion
          next ServiceResponse.error(message: error) if error

          decision.destroy!
          ServiceResponse.success(payload: { decision: decision })
        end
        return response if response.error?

        track_event

        response
      end

      private

      attr_reader :decision, :work_item, :current_user

      # Resolved decisions are part of the audit trail: they can only be
      # archived, or cascade-deleted with the work item
      def validate_deletion
        return _('Archived decisions cannot be deleted') if decision.archived_at?

        _('Resolved decisions cannot be deleted') if decision.resolved_at?
      end

      def track_event
        ::Gitlab::WorkItems::Instrumentation::TrackingService.track_decision_event(
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::DECISION_DESTROY_UNRESOLVED,
          decision: decision,
          current_user: current_user
        )
      end

      # get_widget covers type registration, ai_workflows licensing, and the
      # decision_log feature flag
      def allowed?
        Ability.allowed?(current_user, :update_work_item, work_item) && work_item.get_widget(:decision_log).present?
      end
    end
  end
end
