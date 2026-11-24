# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module Chain
        class Seed < Chain::Base
          include Chain::Helpers
          include Gitlab::Utils::StrongMemoize

          DEFAULT_TIMEOUT_SECONDS = 900
          TIMEOUT_SECONDS = (
            Integer(ENV.fetch('GITLAB_CI_PIPELINE_SEED_TIMEOUT_SECONDS', DEFAULT_TIMEOUT_SECONDS), exception: false) ||
            DEFAULT_TIMEOUT_SECONDS
          ).clamp(1, 1800).seconds
          OVERRIDE_TIMEOUT_SECONDS = 1800.seconds
          TIMEOUT_MESSAGE = 'Pipeline creation timed out while evaluating rules. ' \
            'Pipelines with many jobs defined in the configuration can take longer to evaluate.'

          def perform!
            raise ArgumentError, 'missing YAML processor result' unless @command.yaml_processor_result
            raise ArgumentError, 'missing workflow rules result' unless @command.workflow_rules_result

            # Allocate next IID. This operation must be outside of transactions of pipeline creations.
            logger.instrument(:pipeline_allocate_seed_attributes, once: true) do
              pipeline.ensure_project_iid! if @command.allocate_pipeline_iid?
              pipeline.ensure_ci_ref!
            end

            # Protect the pipeline. This is assigned in Populate instead of
            # Build to prevent erroring out on ambiguous refs.
            pipeline.protected = @command.protected_ref?

            ##
            # Gather all runtime build/stage errors
            #
            seed_errors = logger.instrument(:pipeline_seed_evaluation, once: true) do
              pipeline_seed.errors
            end

            return error(seed_errors.join("\n"), failure_reason: :config_error) if seed_errors

            log_rules_parse_failure_jobs

            @command.pipeline_seed = pipeline_seed
          rescue Gitlab::Ci::Pipeline::Seed::Context::TimeoutError => e
            handle_timeout(e)
          end

          def break?
            pipeline.errors.any?
          end

          private

          def log_rules_parse_failure_jobs
            return if @command.readonly?

            seeds = pipeline_seed.rules_parse_failure_seeds
            return if seeds.empty?

            Gitlab::AppJsonLogger.info(
              class_name: self.class.name,
              message: 'jobs marked as failed because rules could not be evaluated',
              project_id: project.id,
              extra: {
                pipeline_source: @command.source.to_s,
                job_errors: seeds.map { |seed| "#{seed.name}: #{seed.rules_parse_error_message}" }
              }
            )
          end

          def pipeline_seed
            logger.instrument(:pipeline_seed_initialization, once: true) do
              stages_attributes = logger.instrument(:pipeline_seed_initialization_stages_attributes, once: true) do
                @command.yaml_processor_result.stages_attributes
              end

              Gitlab::Ci::Pipeline::Seed::Pipeline.new(context, stages_attributes)
            end
          end
          strong_memoize_attr :pipeline_seed

          def context
            Gitlab::Ci::Pipeline::Seed::Context.new(
              pipeline,
              root_variables: root_variables,
              logger: logger
            ).tap do |ctx|
              ctx.set_deadline(seed_timeout) if Feature.enabled?(:ci_pipeline_seed_timeout, project)
            end
          end
          strong_memoize_attr :context

          def seed_timeout
            if Feature.enabled?(:ci_pipeline_seed_timeout_override, project.root_namespace, type: :ops)
              OVERRIDE_TIMEOUT_SECONDS
            else
              TIMEOUT_SECONDS
            end
          end

          def handle_timeout(exception)
            Gitlab::ErrorTracking.log_exception(
              exception,
              Labkit::Fields::GL_PROJECT_ID => project.id,
              pipeline_source: pipeline.source,
              job_candidates_count: @command.yaml_processor_result.jobs.size,
              evaluated_job_candidates_count: context.evaluated_job_candidates_count
            )

            error(TIMEOUT_MESSAGE, failure_reason: :seed_timeout)
          end

          def root_variables
            ::Gitlab::Ci::Variables::Helpers.merge_variables(
              @command.yaml_processor_result.root_variables,
              @command.workflow_rules_result.variables)
          end
          strong_memoize_attr :root_variables
        end
      end
    end
  end
end
