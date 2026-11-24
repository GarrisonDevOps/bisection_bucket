# frozen_string_literal: true

# The round robin strategy will assign the next variant in the list, looping back to the first variant after all
# variants have been assigned. This is useful for very small sample sizes where very even distribution can be required.
#
# Requires a cache to be configured.
#
# Keeps track of the number of assignments into the experiment group, and uses this to rotate "round robin" style
# through the variants that are defined.
#
# Example configuration usage:
#
# config.default_rollout = Gitlab::Experiment::Rollout::RoundRobin.new
#
# Example class usage:
#
# class PillColorExperiment < ApplicationExperiment
#   control { }
#   variant(:red) { }
#   variant(:blue) { }
#
#   # Rotate evenly between all behaviors.
#   default_rollout :round_robin
# end
#
module Gitlab
  class Experiment
    module Rollout
      class RoundRobin < Base
        KEY_NAME = :last_round_robin_variant

        protected

        def execute_assignment
          behavior_names[(cache.attr_inc(KEY_NAME) - 1) % behavior_names.size]
        end
      end
    end
  end
end
