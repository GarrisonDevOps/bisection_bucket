# frozen_string_literal: true

module WorkItems
  class DecisionResolvedEvent < BaseEvent
    event_type :decision_resolved

    class << self
      def build(decision:, current_user:)
        build_for_work_item(
          work_item: decision.work_item,
          current_user: current_user,
          extra_event_data: { decision_id: decision.id }
        )
      end
    end

    private

    def additional_properties
      { 'decision_id' => { 'type' => 'integer' } }
    end

    def additional_required
      %w[decision_id]
    end
  end
end
