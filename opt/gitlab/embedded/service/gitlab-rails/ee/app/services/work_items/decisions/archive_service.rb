# frozen_string_literal: true

module WorkItems
  module Decisions
    class ArchiveService
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

          error = validate_archival
          next ServiceResponse.error(message: error) if error

          now = Time.current
          # update_columns: archived_at has no validations, and update! would
          # re-run unrelated ones on a record the archive never changes
          decision.update_columns(archived_at: now, updated_at: now)
          ServiceResponse.success(payload: { decision: decision })
        end
        return response if response.error?

        track_event

        response
      end

      private

      attr_reader :decision, :work_item, :current_user

      def validate_archival
        return _('Decision is already archived') if decision.archived_at?

        _('Only resolved decisions can be archived') unless decision.resolved_at?
      end

      def track_event
        ::Gitlab::WorkItems::Instrumentation::TrackingService.track_decision_event(
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::DECISION_ARCHIVE,
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
