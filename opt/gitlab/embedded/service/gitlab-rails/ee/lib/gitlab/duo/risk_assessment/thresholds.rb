# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      # Maps a score (0-100) onto a risk or confidence tier via fixed lower
      # bounds. Kept separate from the score itself so re-tiering later is a
      # threshold change, not a re-scoring run.
      #
      # These bounds are a starting point, not calibrated against real
      # assessments yet -- expect them to move once there's outcome data to
      # tune against.
      module Thresholds
        MIN_SCORE = 0
        MAX_SCORE = 100

        RISK_BOUNDS = {
          low: MIN_SCORE,
          medium: 25,
          high: 50,
          critical: 75
        }.freeze

        CONFIDENCE_BOUNDS = {
          low: MIN_SCORE,
          medium: 25,
          high: 50,
          very_high: 75
        }.freeze

        def self.risk_tier_for(score)
          band_for(score, RISK_BOUNDS)
        end

        def self.confidence_tier_for(score)
          band_for(score, CONFIDENCE_BOUNDS)
        end

        def self.valid?(score)
          score.is_a?(Integer) && score.between?(MIN_SCORE, MAX_SCORE)
        end

        def self.band_for(score, bounds)
          return unless valid?(score)

          bounds.reverse_each.find { |_band, lower_bound| score >= lower_bound }.first
        end
        private_class_method :band_for
      end
    end
  end
end
