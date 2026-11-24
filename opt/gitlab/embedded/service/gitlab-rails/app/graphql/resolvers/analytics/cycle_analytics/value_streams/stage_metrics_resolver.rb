# frozen_string_literal: true

module Resolvers
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class StageMetricsResolver < BaseResolver
          type ::Types::Analytics::CycleAnalytics::ValueStreams::StageMetricsType, null: true

          RATE_LIMIT_KEY = :value_stream_stage_metrics

          argument :timeframe, Types::TimeframeInputType,
            required: true,
            description: 'Aggregation timeframe. Filters the issue or the merge request creation time for FOSS ' \
              'projects, and the end event timestamp for licensed projects or groups. Maximum of 180 days when ' \
              'the `vsa_stage_metrics_validate_timeframe` feature flag is enabled. ' \
              'No maximum when the flag is disabled.'

          argument :assignee_usernames, [GraphQL::Types::String],
            required: false,
            description: 'Usernames of users assigned to the issue or the merge request.'

          argument :author_username, GraphQL::Types::String,
            required: false,
            description: 'Username of the author of the issue or the merge request.'

          argument :milestone_title, GraphQL::Types::String,
            required: false,
            description: 'Milestone applied to the issue or the merge request.'

          argument :label_names, [GraphQL::Types::String],
            required: false,
            description: 'Labels applied to the issue or the merge request.'

          def resolve(**args)
            request_params = transform_params(args, object)
            validate_request_params!(request_params)
            check_rate_limit!

            Gitlab::Analytics::CycleAnalytics::DataCollector.new(stage: object,
              params: request_params.to_data_collector_params)
          end

          private

          # Runs once per stage, so a query pays for every stage it asks metrics for.
          def check_rate_limit!
            return unless throttled?

            raise_resource_not_available_error!(Gitlab::ApplicationRateLimiter.throttled_error_message)
          end

          def throttled?
            request = context[:request]
            scope = rate_limit_scope(request)
            return false unless scope

            if request
              Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, RATE_LIMIT_KEY, scope: scope)
            else
              Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: scope)
            end
          end

          # GraphqlChannel carries no request; the ActionCable worker sets IpAddressState.
          # Without an IP there is nothing to key an anonymous caller on, so skip the check
          # rather than put every such caller in one bucket.
          def rate_limit_scope(request)
            return { user: current_user } if current_user

            ip = request&.ip.presence || Gitlab::IpAddressState.current.presence
            { ip: ip } if ip
          end

          def validate_request_params!(request_params)
            root = object.namespace.root_ancestor
            return unless Feature.enabled?(:vsa_stage_metrics_validate_timeframe, root, type: :gitlab_com_derisk)
            return if request_params.valid?

            raise Gitlab::Graphql::Errors::ArgumentError, request_params.errors.map(&:message).to_sentence
          end

          def transform_params(args, _stage)
            formatted_args = args.to_hash
            timeframe = args.delete(:timeframe)
            formatted_args[:created_after] = timeframe[:start]
            formatted_args[:created_before] = timeframe[:end]

            if formatted_args[:assignee_usernames].present?
              formatted_args[:assignee_username] =
                formatted_args.delete(:assignee_usernames)
            end

            formatted_args[:label_name] = formatted_args.delete(:label_names) if formatted_args[:label_names].present?

            Gitlab::Analytics::CycleAnalytics::RequestParams.new(
              namespace: object.namespace,
              current_user: current_user,
              **formatted_args.compact
            )
          end
        end
      end
    end
  end
end

Resolvers::Analytics::CycleAnalytics::ValueStreams::StageMetricsResolver.prepend_mod
