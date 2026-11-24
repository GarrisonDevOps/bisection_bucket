# frozen_string_literal: true

module Mutations
  module Ai
    module ModelSelection
      module Namespaces
        class Update < BaseMutation
          graphql_name 'AiModelSelectionNamespaceUpdate'
          description "Updates or creates settings for AI features for a namespace."
          authorize :admin_group_model_selection
          authorize_granular_token permissions: :update_model_selection,
            boundary_argument: :group_id, boundary_type: :group

          RATE_LIMIT_KEY = :ai_model_selection_namespace_update

          field :ai_feature_settings,
            [::Types::Ai::ModelSelection::Namespaces::FeatureSettingType],
            null: false,
            description: 'List of AI feature settings after mutation.',
            experiment: { milestone: '18.1' }

          argument :group_id, ::Types::GlobalIDType[::Group],
            required: true,
            description: 'Group for the model selection.'

          argument :features, [::Types::Ai::ModelSelection::FeaturesEnum],
            required: true,
            description: 'Array of AI features being configured (for single or batch update).'

          argument :offered_model_ref, GraphQL::Types::String,
            required: true,
            description: 'Identifier of the selected model for the feature.'

          def resolve(**args)
            @group_id = args[:group_id]
            group = authorized_find!(id: group_id)

            check_rate_limit!

            features = args[:features]

            return error_response('At least one feature is required') if features.empty?

            return error_response('Features must not contain duplicates') if features.uniq.size != features.size

            return error_response(catalog.error_message) unless catalog.success?

            upsert_args = args.except(:features, :group_id)

            results = features.map do |feature|
              upsert_feature_setting(group, upsert_args.merge(feature: feature))
            end

            errors = results.select(&:error?).flat_map(&:errors)
            feature_settings = results.reject(&:error?).flat_map(&:payload)

            # Feature settings skipped as unchanged have no model_definitions of their own,
            # so decorate with the request's catalog.
            decorated_feature_settings = ::Gitlab::Graphql::Representation::ModelSelection::FeatureSetting
                                           .decorate(feature_settings, model_definitions: catalog.payload,
                                             current_user: current_user)

            {
              ai_feature_settings: decorated_feature_settings,
              errors: errors
            }
          end

          private

          attr_reader :group_id

          def error_response(message)
            { ai_feature_settings: [], errors: [message] }
          end

          def check_rate_limit!
            return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

            raise ::RateLimitedService::RateLimitedError.new(
              key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
            ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
          end

          def upsert_feature_setting(group, args)
            feature_setting = find_or_initialize_object(group, feature: args[:feature])

            ::Ai::ModelSelection::Namespace::UpdateService.new(
              feature_setting, current_user, args, catalog: catalog
            ).execute
          end

          def find_or_initialize_object(group, feature:)
            ::Ai::ModelSelection::NamespaceFeatureSetting.find_or_initialize_by_feature(group, feature)
          end

          def catalog
            @catalog ||= ::Ai::ModelSelection::ModelDefinitions.fetch(current_user)
          end
        end
      end
    end
  end
end
