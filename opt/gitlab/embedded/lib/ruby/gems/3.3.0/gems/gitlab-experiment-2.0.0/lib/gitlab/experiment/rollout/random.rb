# frozen_string_literal: true

# The random rollout strategy picks a variant uniformly at random the first time a context is assigned into the
# experiment group.
#
# If caching is enabled, that first roll is persisted and the context gets the same variant on every subsequent visit,
# so the assignment is stable/sticky per context -- including :control, which is cached like any other variant. Without
# caching, assignment is random on every call.
#
# Example configuration usage:
#
# config.default_rollout = Gitlab::Experiment::Rollout::Random.new
#
# Example class usage:
#
# class PillColorExperiment < ApplicationExperiment
#   control { }
#   variant(:red) { }
#   variant(:blue) { }
#
#   # Randomize between all behaviors, with a mostly even distribution).
#   default_rollout :random
# end
#
module Gitlab
  class Experiment
    module Rollout
      class Random < Base
        protected

        def execute_assignment
          behavior_names.sample # pick a random variant; cached on first roll so it stays stable
        end
      end
    end
  end
end
