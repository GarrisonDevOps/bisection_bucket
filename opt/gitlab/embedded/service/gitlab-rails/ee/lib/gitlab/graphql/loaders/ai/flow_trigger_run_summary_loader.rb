# frozen_string_literal: true

module Gitlab
  module Graphql
    module Loaders
      module Ai
        class FlowTriggerRunSummaryLoader
          Summary = Struct.new(:last_run, :running_count)
          LastRun = Struct.new(:status, :started_at, :finished_at, :error, keyword_init: true)

          def self.visible_workflows(project, flow_triggers, current_user)
            return ::Ai::DuoWorkflows::Workflow.none unless project

            ActiveRecord::Associations::Preloader.new(
              records: flow_triggers,
              associations: { ai_catalog_item_consumer: :parent_item_consumer }
            ).call

            ::Ai::DuoWorkflows::WorkflowsFinder
              .new(source: project, current_user: current_user, flow_triggers: flow_triggers)
              .results
          end

          def initialize(flow_trigger, current_user)
            @flow_trigger = flow_trigger
            @current_user = current_user
          end

          def find
            BatchLoader::GraphQL.for(flow_trigger)
              .batch(key: [flow_trigger.project_id, current_user]) do |flow_triggers, loader|
              workflows = self.class.visible_workflows(flow_triggers.first.project, flow_triggers, current_user)
              latest_workflows = workflows.latest_for_flow_triggers(flow_triggers).index_by(&:trigger_flow_trigger_id)
              running_counts = workflows.active_counts_per_flow_trigger
              schedule_failures = ::Ai::FlowSchedule.failed_for_flow_triggers(flow_triggers)
                .group_by(&:ai_flow_trigger_id)
                .transform_values { |schedules| schedules.max_by(&:last_run_at) }

              flow_triggers.each do |trigger|
                last_run = build_last_run(latest_workflows[trigger.id], schedule_failures[trigger.id])

                loader.call(trigger, Summary.new(last_run, running_counts.fetch(trigger.id, 0)))
              end
            end
          end

          private

          attr_reader :flow_trigger, :current_user

          def build_last_run(workflow, schedule_failure)
            if schedule_failure && (workflow.nil? || schedule_failure.last_run_at > workflow.created_at)
              LastRun.new(
                status: :failed,
                started_at: schedule_failure.last_run_at,
                finished_at: schedule_failure.last_run_at,
                error: schedule_failure.last_run_error
              )
            elsif workflow
              LastRun.new(
                status: ::Ai::FlowTrigger::RUN_STATUSES.fetch(workflow.status_name),
                started_at: workflow.created_at,
                finished_at: (workflow.updated_at if workflow.status_terminal?)
              )
            end
          end
        end
      end
    end
  end
end
