# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      # Versioned scoring functions.
      #
      # Every assessment records the version that produced it, so a score stays
      # interpretable after the model is retuned. Recalibration ships as a new
      # version rather than a change to an existing one, which is what lets a
      # later pass compare like with like.
      module ScoringFunction
        class << self
          def current
            V1
          end

          # @return [Array<Class>] every version, oldest first.
          def all
            [V1]
          end

          # @param version [String, Symbol] as stored on an assessment
          # @return [Class, nil]
          def for_version(version)
            all.find { |scoring_function| scoring_function.version == version.to_s }
          end
        end
      end
    end
  end
end
