# frozen_string_literal: true

module EE
  module Resolvers
    module Analytics
      module CycleAnalytics
        module ValueStreams
          module StageMetricsResolver
            extend ActiveSupport::Concern

            UNSUPPORTED_PARAMS_FOR_MERGE_REQUEST = %I[epic_id iteration_id weight].freeze

            prepended do
              include ResolvesIds

              argument :epic_id, ::GraphQL::Types::ID,
                required: false,
                description: "ID of an epic associated with the issues. \
              Using the filter is not supported for stages based on merge requests."

              argument :iteration_id, ::GraphQL::Types::ID,
                required: false,
                description: "ID of an iteration associated with the issues. \
              Using the filter is not supported for stages based on merge requests."

              argument :weight, GraphQL::Types::Int,
                required: false,
                description: "Weight applied to the issue. \
              Using the filter is not supported for stages based on merge requests."

              argument :my_reaction_emoji, GraphQL::Types::String,
                required: false,
                description: ::Resolvers::Analytics::CycleAnalytics::BaseIssueResolver
                  .arguments['myReactionEmoji']
                  .description

              argument :not, ::Types::Analytics::CycleAnalytics::NegatedIssuableFilterInputType,
                required: false,
                description: ::Resolvers::Analytics::CycleAnalytics::BaseIssueResolver.arguments['not'].description

              argument :project_ids, [::Types::GlobalIDType[::Project]],
                required: false,
                description: 'Filter for projects. Only available for group value streams.'
            end

            private

            def ready?(**args)
              if !object.value_stream.at_group_level? && args[:project_ids].present?
                raise ::Gitlab::Graphql::Errors::ArgumentError,
                  "Project value streams don't support the projectIds filter"
              end

              super
            end

            def transform_params(args, stage)
              formatted_args = args.to_hash
              formatted_args[:not] = formatted_args[:not].to_hash if formatted_args[:not]
              formatted_args[:project_ids] = resolve_ids(formatted_args[:project_ids]) if formatted_args[:project_ids]

              move_not_param(formatted_args, :assignee_usernames, :assignee_username)
              move_not_param(formatted_args, :label_names, :label_name)

              validate_params!(args, stage)

              super(formatted_args, stage)
            end

            def move_not_param(args, from, to)
              return unless args[:not]
              return unless args[:not][from]

              args[:not][to] = args[:not].delete(from)
            end

            def validate_params!(args, stage)
              return if stage.subject_class.is_a?(Issue)

              UNSUPPORTED_PARAMS_FOR_MERGE_REQUEST.each do |key|
                if args[key] || (args[:not] && args[:not][key])
                  raise ::Gitlab::Graphql::Errors::ArgumentError,
                    "Unsupported filter argument for Merge Request based stages: #{key}"
                end
              end
            end
          end
        end
      end
    end
  end
end
