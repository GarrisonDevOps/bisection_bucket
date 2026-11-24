# frozen_string_literal: true

module Gitlab
  module Graphql
    module Loaders
      module Ai
        class FlowTriggerRunStatsLoader
          EMPTY_RUN_STATS = {
            total_runs: 0, finished_runs: 0, failed_runs: 0, stopped_runs: 0, median_duration_seconds: nil
          }.freeze

          def initialize(flow_trigger, current_user)
            @flow_trigger = flow_trigger
            @current_user = current_user
          end

          def find
            BatchLoader::GraphQL.for(flow_trigger)
              .batch(key: [flow_trigger.project_id, current_user]) do |flow_triggers, loader|
              project = flow_triggers.first.project
              workflows = FlowTriggerRunSummaryLoader.visible_workflows(project, flow_triggers, current_user)
                .created_after_in_project(project, ::Ai::FlowTrigger::RUN_STATS_WINDOW.ago)
              run_stats = workflows.run_stats_per_flow_trigger
              daily_runs = workflows.daily_runs_per_flow_trigger

              flow_triggers.each do |trigger|
                loader.call(trigger, run_stats.fetch(trigger.id, EMPTY_RUN_STATS)
                  .merge(daily_volume: daily_runs.fetch(trigger.id, [])))
              end
            end
          end

          private

          attr_reader :flow_trigger, :current_user
        end
      end
    end
  end
end
