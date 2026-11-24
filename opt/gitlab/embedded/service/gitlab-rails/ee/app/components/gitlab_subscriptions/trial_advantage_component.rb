# frozen_string_literal: true

module GitlabSubscriptions
  class TrialAdvantageComponent < ViewComponent::Base
    delegate :sprite_icon, to: :helpers

    def initialize(advantage)
      @advantage = advantage
    end
  end
end
