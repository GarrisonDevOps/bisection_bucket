# frozen_string_literal: true

module Search
  module Concerns
    module FeatureCustomAbilityMap
      extend ActiveSupport::Concern

      # maps <feature>_access_level to custom role abilities
      FEATURE_TO_ABILITY_MAP = {
        repository: :read_code
      }.freeze
    end
  end
end
