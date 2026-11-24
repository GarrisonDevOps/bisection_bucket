# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module Seed
        class Build < Seed::Base
          include Gitlab::Utils::StrongMemoize

          NULL_BYTE_ERROR = 'contains a null byte. For escape codes, use "\e" or "\\\\033" instead of "\033".'

          delegate :dig, to: :@seed_attributes

          def initialize(context, attributes, stages_for_needs_lookup)
            @context = context
            @pipeline = context.pipeline
            @seed_attributes = attributes
            @stages_for_needs_lookup = stages_for_needs_lookup.compact
            @needs_attributes = dig(:needs_attributes)
            @resource_group_key = attributes.delete(:resource_group_key)
            @job_variables = @seed_attributes.delete(:job_variables)
            @execution_config_attribute = @seed_attributes.delete(:execution_config)
            @root_variables_inheritance = @seed_attributes.delete(:root_variables_inheritance) { true }
            @inputs = @seed_attributes.delete(:inputs)

            @using_rules  = attributes.key?(:rules)
            @using_only   = attributes.key?(:only)
            @using_except = attributes.key?(:except)

            @only = Gitlab::Ci::Build::Policy
              .fabricate(attributes.delete(:only))
            @except = Gitlab::Ci::Build::Policy
              .fabricate(attributes.delete(:except))
            @rules = Gitlab::Ci::Build::Rules
              .new(attributes.delete(:rules), default_when: attributes[:when])
            @cache = Gitlab::Ci::Build::Cache
              .new(attributes.delete(:cache), @pipeline)

            calculate_yaml_variables!
          end

          def name
            dig(:name)
          end

          # Set by Seed::Stage when dropping this build would discard its rules error.
          def mark_rules_parse_failure!
            @rules_parse_failure = true
            clear_memoization(:included?)
            clear_memoization(:errors)
          end

          def rules_parse_failure?
            !!@rules_parse_failure
          end

          def rules_parse_error_message
            rules_result.errors.join(', ')
          end

          def rules_parse_error?
            rules_result.errors.present?
          end
          strong_memoize_attr :rules_parse_error?

          def included?
            @context.check_execution_time!

            logger.instrument(:pipeline_seed_build_inclusion) do
              next true if @rules_parse_failure

              if @using_rules
                rules_result.pass?
              elsif @using_only || @using_except
                all_of_only? && none_of_except?
              else
                true
              end
            end
          end
          strong_memoize_attr :included?

          def errors
            logger.instrument(:pipeline_seed_build_errors) do
              # Carried on the job itself, so it must not also fail pipeline creation.
              next if @rules_parse_failure
              # We check rules errors before checking "included?" because rules affects its inclusion status.
              next rules_errors if rules_errors
              next unless included?

              [needs_errors, variable_expansion_errors, null_byte_errors].compact.flatten
            end
          end
          strong_memoize_attr :errors

          def attributes
            @seed_attributes
              .deep_merge(pipeline_attributes)
              .deep_merge(rules_attributes)
              .deep_merge(rules_parse_error_attributes)
              .deep_merge(allow_failure_criteria_attributes)
              .deep_merge(@cache.cache_attributes)
              .deep_merge(inputs_attributes)
              .deep_merge(runner_tags)
              .deep_merge(scoped_user_id_attribute)
              .then { |attrs| add_execution_config(attrs) }
              .except(:stage)
          end

          def bridge?
            attributes_hash = @seed_attributes.to_h
            attributes_hash.dig(:options, :trigger).present? ||
              (attributes_hash.dig(:options, :bridge_needs).instance_of?(Hash) &&
               attributes_hash.dig(:options, :bridge_needs, :pipeline).present?)
          end

          def deployment?
            dig(:environment).present?
          end

          def to_resource
            logger.instrument(:pipeline_seed_build_to_resource) do
              resource =
                if bridge?
                  ::Ci::Bridge.fabricate(**attributes)
                else
                  ::Ci::Build.fabricate(**attributes)
                end

              add_rules_parse_error_message(resource)

              resource
            end
          end
          strong_memoize_attr :to_resource

          private

          delegate :logger, to: :@context

          # Chain::Create persists this: bulk insert skips autosave.
          def add_rules_parse_error_message(resource)
            return unless @rules_parse_failure

            resource.job_messages.build(
              content: rules_parse_error_message,
              severity: :error,
              project_id: resource.project_id,
              partition_id: resource.partition_id
            )
          end

          def all_of_only?
            @only.all? { |spec| spec.satisfied_by?(@pipeline, evaluate_context) }
          end

          def none_of_except?
            @except.none? { |spec| spec.satisfied_by?(@pipeline, evaluate_context) }
          end

          def needs_errors
            return if @needs_attributes.nil?

            if @needs_attributes.size > max_needs_allowed
              return [
                "#{name}: one job can only need #{max_needs_allowed} others, but you have listed #{@needs_attributes.size}. " \
                  "See needs keyword documentation for more details"
              ]
            end

            @needs_attributes.flat_map do |need|
              # We ignore the optional needed job in case it is excluded from the pipeline due to the job's rules.
              next if need[:optional]

              result = need_present?(need)

              unless result
                next "'#{name}' job needs '#{need[:name]}' job, but '#{need[:name]}' does not exist in the pipeline. " \
                  'This might be because of the only, except, or rules keywords. ' \
                  'To need a job that sometimes does not exist in the pipeline, use needs:optional.'
              end

              # A job whose rules could not be evaluated produces nothing, so needing it is unsafe.
              needed_seed = find_need_seed(need)
              next rules_parse_failure_need_error(need, needed_seed) if needed_seed&.rules_parse_failure?
            end.compact
          end

          def find_need_seed(need)
            @stages_for_needs_lookup.lazy.filter_map { |stage| stage.find_seed_by_name(need[:name]) }.first
          end

          def rules_parse_failure_need_error(need, needed_seed)
            "'#{name}' job needs '#{need[:name]}' job, but the rules for '#{need[:name]}' could not be " \
              "evaluated: #{needed_seed.rules_parse_error_message}"
          end

          def need_present?(need)
            @stages_for_needs_lookup.any? do |stage|
              stage.seeds_names.include?(need[:name])
            end
          end

          def max_needs_allowed
            @pipeline.project.actual_limits.ci_needs_size_limit
          end

          def variable_expansion_errors
            expanded_collection = evaluate_context.variables_sorted_and_expanded
            errors = expanded_collection.errors
            ["#{name}: #{errors}"] if errors
          end

          # PostgreSQL cannot store null bytes, so saving the job would fail.
          def null_byte_errors
            ["#{name.delete("\0")}: #{NULL_BYTE_ERROR}"] if contains_null_byte?(attributes)
          end

          def contains_null_byte?(value)
            case value
            when Hash then value.any? { |key, val| contains_null_byte?(key.to_s) || contains_null_byte?(val) }
            when Array then value.any? { |val| contains_null_byte?(val) }
            when String then value.include?("\0")
            else false
            end
          end

          def pipeline_attributes
            {
              pipeline: @pipeline,
              project: @pipeline.project,
              user: @pipeline.user,
              ref: @pipeline.ref,
              tag: @pipeline.tag,
              protected: @pipeline.protected_ref?,
              partition_id: @pipeline.partition_id
            }
          end

          # Scoped user is present when the user creating the pipeline supports composite identity.
          # For example: a service account like GitLab Duo. The scoped user is used to further restrict
          # the permissions of the CI job token associated to the `job.user`.
          def scoped_user_id_attribute
            user_identity = ::Gitlab::Auth::Identity.fabricate(@pipeline.user)

            return {} unless user_identity&.composite? && user_identity.linked?

            { scoped_user_id: user_identity.scoped_user.id }
          end

          def rules_attributes
            return {} unless @using_rules

            rules_variables_result = ::Gitlab::Ci::Variables::Helpers.merge_variables(
              @seed_attributes[:yaml_variables], rules_result.variables
            )

            rules_result.build_attributes.merge(yaml_variables: rules_variables_result)
          end
          strong_memoize_attr :rules_attributes

          def rules_result
            @rules.evaluate(@pipeline, evaluate_context)
          end
          strong_memoize_attr :rules_result

          def rules_errors
            ["Failed to parse rule for #{name}: #{rules_result.errors.join(', ')}"] if rules_result.errors.present?
          end
          strong_memoize_attr :rules_errors

          # The rules result carries `never`, which must not be persisted on a job that exists.
          def rules_parse_error_attributes
            return {} unless @rules_parse_failure

            {
              when: 'on_success',
              status: :failed,
              failure_reason: :rules_parse_failure,
              allow_failure: true
            }
          end

          def evaluate_context
            Gitlab::Ci::Build::Context::Build.new(@pipeline, @seed_attributes, logger: logger)
          end
          strong_memoize_attr :evaluate_context

          def runner_tags
            { tag_list: evaluate_runner_tags }.compact
          end
          strong_memoize_attr :runner_tags

          def evaluate_runner_tags
            @seed_attributes.delete(:tag_list)&.map do |tag|
              ExpandVariables.expand_existing(tag, -> { evaluate_context.variables_hash })
            end
          end

          # If a job uses `allow_failure:exit_codes` and `rules:allow_failure`
          # we need to prevent the exit codes from being persisted because they
          # would break the behavior defined by `rules:allow_failure`.
          def allow_failure_criteria_attributes
            return {} if rules_attributes[:allow_failure].nil?
            return {} unless @seed_attributes.dig(:options, :allow_failure_criteria)

            { options: { allow_failure_criteria: nil } }
          end

          def inputs_attributes
            return {} unless @inputs

            {
              options: { inputs: @inputs }
            }
          end

          def calculate_yaml_variables!
            @seed_attributes[:yaml_variables] = Gitlab::Ci::Variables::Helpers.inherit_yaml_variables(
              from: @context.root_variables, to: @job_variables, inheritance: @root_variables_inheritance
            )
          end

          def add_execution_config(attrs)
            return attrs unless @execution_config_attribute

            # Currently, `execution_config` is passed from `lib/gitlab/ci/yaml_processor/result.rb` and deleted
            # in the `initialize` method of this class and assigned to `@execution_config_attribute`.
            # Today, we don't want to make a huge change in the process; we only want to save the data to the
            # `p_ci_job_definitions` table.
            attrs.merge(@execution_config_attribute)
          end
        end
      end
    end
  end
end
