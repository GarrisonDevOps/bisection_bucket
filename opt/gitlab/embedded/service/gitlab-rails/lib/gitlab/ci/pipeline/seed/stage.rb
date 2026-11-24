# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module Seed
        class Stage < Seed::Base
          include Gitlab::Utils::StrongMemoize

          delegate :size, to: :seeds
          delegate :dig, to: :seeds

          def initialize(context, attributes, previous_stages)
            @context = context
            @pipeline = context.pipeline
            @attributes = attributes
            @previous_stages = previous_stages

            @builds = attributes.fetch(:builds).map do |attributes|
              Seed::Build.new(context, attributes, previous_stages + [self])
            end
          end

          def attributes
            { name: @attributes.fetch(:name),
              position: @attributes.fetch(:index),
              pipeline: @pipeline,
              project: @pipeline.project,
              partition_id: @pipeline.partition_id }
          end

          def seeds
            return included_seeds if included_seeds.any?

            # Dropping the stage would discard any rules error its builds recorded.
            @builds.select(&:rules_parse_error?).each(&:mark_rules_parse_failure!)
          end
          strong_memoize_attr :seeds

          def errors
            seeds # must run first: marking there decides whether a build reports its rules error

            @builds.flat_map(&:errors).compact
          end
          strong_memoize_attr :errors

          def included_seeds
            @builds.select(&:included?)
          end
          strong_memoize_attr :included_seeds

          def seeds_names
            seeds.map(&:name).to_set
          end
          strong_memoize_attr :seeds_names

          def find_seed_by_name(name)
            seeds_by_name[name]
          end

          def seeds_by_name
            seeds.index_by(&:name)
          end
          strong_memoize_attr :seeds_by_name

          def deployments_count
            seeds.count(&:deployment?)
          end
          strong_memoize_attr :deployments_count

          def included?
            seeds.any?
          end

          def to_resource
            ::Ci::Stage.new(attributes).tap do |stage|
              stage.statuses = seeds.map(&:to_resource)
            end
          end
          strong_memoize_attr :to_resource
        end
      end
    end
  end
end
