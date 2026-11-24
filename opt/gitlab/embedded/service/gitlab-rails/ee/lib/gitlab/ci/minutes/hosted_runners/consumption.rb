# frozen_string_literal: true

module Gitlab
  module Ci
    module Minutes
      module HostedRunners
        class Consumption
          include Gitlab::Utils::StrongMemoize

          def initialize(pipeline:, runner_matcher:, duration:)
            @pipeline = pipeline
            @runner_matcher = runner_matcher
            @duration = duration
          end

          def amount
            @amount ||= (duration.to_f / 60 * dedicated_hosted_runners_cost_factor).round(2)
          end

          private

          attr_reader :pipeline, :runner_matcher, :duration

          def dedicated_hosted_runners_cost_factor
            Gitlab::Ci::Minutes::RunnerCostFactor.new(runner_matcher, pipeline.project).value.tap do |factor|
              log_cost_factor(factor)
            end
          end

          def log_cost_factor(factor)
            Gitlab::AppLogger.info(
              cost_factor: factor,
              project_path: pipeline.project.full_path,
              pipeline_id: pipeline.id,
              class: self.class.name
            )
          end
        end
      end
    end
  end
end
