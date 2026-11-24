# frozen_string_literal: true

module SeatAlert
  class BaseComponent < ViewComponent::Base
    private

    # Small subscriptions sit at their seat limit as a matter of course, so a seat-limit alert
    # carries no actionable signal for them. Subclasses provide total_user_count.
    def small_subscription?
      ::GitlabSubscriptions::SeatThresholds.small_subscription?(total_user_count)
    end

    def render_component
      self.class::COMPONENT_BY_STATE.fetch(seat_state).new
    end

    def seat_state
      if remaining_user_count > 0
        :threshold
      elsif remaining_user_count == 0
        :reached
      else
        :overage
      end
    end
  end
end
