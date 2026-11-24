# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      # rubocop: disable Graphql/AuthorizeTypes -- always authorized by Resolver
      class UserMetricsType < BaseObject
        graphql_name 'AiUserMetrics'
        description "Pre-aggregated per-user metrics for GitLab Code Suggestions and GitLab Duo Chat. " \
          "Requires ClickHouse to be enabled. Premium or Ultimate only."

        authorize_granular_token skip_reason: :parent_authorizes

        include ::Analytics::AiEventFields

        ALL_FEATURES = ::Analytics::AiAnalytics::AiUserMetricsService::ALL_FEATURES

        field :user, Types::GitlabSubscriptions::AddOnUserType,
          description: 'User associated with metrics.',
          null: true

        field :code_suggestions_accepted_count, GraphQL::Types::Int,
          description: 'Total count of code suggestions accepted by the user.',
          null: true,
          deprecated: {
            reason: 'Use `codeSuggestions.codeSuggestionAcceptedInIdeEventCount` instead', milestone: '18.7'
          }

        field :duo_chat_interactions_count, GraphQL::Types::Int,
          description: 'Number of user interactions with GitLab Duo Chat.',
          null: true,
          deprecated: { reason: 'Use `chat.requestDuoChatResponseEventCount` instead', milestone: '18.7' }

        field :total_event_count, GraphQL::Types::Int,
          description: 'Total count of all tracked events for the user.',
          null: true

        field :last_duo_activity_on, Types::DateType,
          description: 'Date of the last Duo activity across all features for the user.',
          null: true

        field :troubleshoot_job, FeatureUserMetricType[:troubleshoot_job],
          description: 'Troubleshoot Job metrics for the user.',
          null: true,
          deprecated: {
            reason: "Legacy troubleshoot job metrics for the user (event ID 7 only). " \
              "For current GitLab Duo Agent Platform-based troubleshoot jobs, use `agentPlatformSessions` " \
              "with `flow_type = 'fix_pipeline/v1'`",
            milestone: '19.1'
          }

        def self.standard_features
          @standard_features ||= Gitlab::Tracking::AiTracking.registered_features - [:troubleshoot_job]
        end

        standard_features.each do |feature|
          field feature, FeatureUserMetricType[feature],
            description: "#{feature.to_s.titleize} metrics for the user.",
            null: true
        end

        def user
          BatchLoader::GraphQL.for(object['user_id']).batch(key: :ai_metrics_users) do |user_ids, loader|
            User.id_in(user_ids).each { |u| loader.call(u.id, u) }
          end
        end

        Gitlab::Tracking::AiTracking.registered_features.each do |feature|
          define_method(feature) do
            load_metrics_for_feature(feature)
          end
        end

        def code_suggestions_accepted_count
          ::Gitlab::Graphql::Lazy.with_value(load_metrics_for_feature(:code_suggestions)) do |metrics|
            metrics[:code_suggestion_accepted_in_ide_event_count] || 0
          end
        end

        def duo_chat_interactions_count
          ::Gitlab::Graphql::Lazy.with_value(load_metrics_for_feature(:chat)) do |metrics|
            metrics[:request_duo_chat_response_event_count] || 0
          end
        end

        def total_event_count
          ::Gitlab::Graphql::Lazy.with_value(load_all_features_metrics) do |metrics|
            metrics[:total_events_count] || 0
          end
        end

        def last_duo_activity_on
          ::Gitlab::Graphql::Lazy.with_value(load_all_features_metrics) do |metrics|
            metrics[:last_duo_activity_on]
          end
        end

        private

        def load_all_features_metrics
          BatchLoader::GraphQL.for(object['user_id'])
            .batch(key: :user_metrics_all_features) do |user_ids, return_result|
            all_metrics = fetch_metrics_for_user_ids(user_ids, ALL_FEATURES)
            user_ids.each do |user_id|
              return_result.call(user_id, all_metrics[user_id] || {})
            end
          end
        end

        def load_metrics_for_feature(feature)
          BatchLoader::GraphQL.for(object['user_id'])
            .batch(key: :"user_metrics_#{feature}") do |user_ids, return_result|
            all_metrics = fetch_metrics_for_user_ids(user_ids, feature)
            user_ids.each do |user_id|
              return_result.call(user_id, all_metrics[user_id] || {})
            end
          end
        end

        def fetch_metrics_for_user_ids(user_ids, feature)
          service_response = ::Analytics::AiAnalytics::AiUserMetricsService.new(
            current_user: context[:current_user],
            namespace: ai_metrics_params[:namespace],
            from: ai_metrics_params[:start_date],
            to: ai_metrics_params[:end_date],
            feature: feature,
            user_ids: user_ids
          ).execute

          return {} unless service_response.success?

          rows = ::Gitlab::ApplicationContext.with_context(namespace: ai_metrics_params[:namespace]) do
            ClickHouse::Client.select(service_response.payload, :main)
          end

          rows.each_with_object({}) do |row, result|
            result[row['user_id']] = row.except('user_id').transform_keys(&:to_sym)
          end
        end

        def ai_metrics_params
          @ai_metrics_params ||= context[:ai_metrics_params] || {}
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
