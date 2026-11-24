# frozen_string_literal: true

require "zlib"

# The percent rollout strategy is the most comprehensive included with Gitlab::Experiment. It allows specifying the
# percentages per variant using an array, a hash, or will default to even distribution when no rules are provided.
#
# A given experiment id (context key) will always be given the same variant assignment.
#
# Example configuration usage:
#
# config.default_rollout = Gitlab::Experiment::Rollout::Percent.new
#
# Example class usage:
#
# class PillColorExperiment < ApplicationExperiment
#   control { }
#   variant(:red) { }
#   variant(:blue) { }
#
#   # Even distribution between all behaviors.
#   default_rollout :percent
#
#   # With specific distribution percentages.
#   default_rollout :percent, distribution: { control: 25, red: 30, blue: 45 }
# end
#
module Gitlab
  class Experiment
    module Rollout
      class Percent < Base
        protected

        def validate!
          case distribution_rules
          when nil then nil
          when Array
            validate_distribution_rules(distribution_rules)
          when Hash
            validate_distribution_rules(distribution_rules.values)
          else
            raise InvalidRolloutRules, 'unknown distribution options type'
          end
        end

        def execute_assignment
          crc = normalized_id
          total = 0

          case distribution_rules
          when Array # run through the rules until finding an acceptable one
            index = distribution_rules.find_index { |percent| crc % 100 < total += percent unless percent == 0 }
            behavior_names[index]
          when Hash # run through the variant names until finding an acceptable one
            distribution_rules.find { |_, percent| crc % 100 < total += percent unless percent == 0 }.first
          else # assume even distribution on no rules
            behavior_names.empty? ? nil : behavior_names[crc % behavior_names.length]
          end
        end

        private

        def normalized_id
          Zlib.crc32(id, nil)
        end

        def distribution_rules
          options[:distribution]
        end

        def validate_distribution_rules(distributions)
          if distributions.length != behavior_names.length
            raise InvalidRolloutRules, "the distribution rules don't match the number of behaviors defined"
          end

          if distributions.any? { |percent| percent < 0 }
            raise InvalidRolloutRules, "the distribution percentage cannot be negative"
          end

          return if distributions.sum == 100

          raise InvalidRolloutRules, 'the distribution percentages should add up to 100'
        end
      end
    end
  end
end
