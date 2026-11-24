# frozen_string_literal: true

module GitlabSubscriptions
  class TrialAdvantagesComponent < ViewComponent::Base
    renders_one :header
    renders_many :advantages, TrialAdvantageComponent
    renders_one :footer
  end
end
