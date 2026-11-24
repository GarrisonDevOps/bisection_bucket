# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module BudgetCaps
      class UpsertUserOverrides < BaseMutation
        graphql_name 'UpsertUserBudgetCapOverrides'

        authorize_granular_token permissions: :update_subscription_usage_cap,
          boundaries: [
            { boundary_argument: :namespace_path, boundary_type: :group },
            { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
          ]

        include ResolvesSubscriptionTarget

        description 'Bulk upsert per-user budget cap overrides.'

        argument :overrides,
          [UserOverrideInputType],
          required: true,
          description: 'List of per-user budget cap overrides to upsert.'

        argument :namespace_path, GraphQL::Types::String,
          required: false,
          description: 'Path of the top-level group namespace. ' \
            'Omit for self-managed instance scope.'

        argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
          required: false,
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          experiment: { milestone: '19.6' },
          description: 'Global ID of the organization.'

        validates mutually_exclusive: [:namespace_path, :organization_id]

        field :user_overrides,
          [::Types::GitlabSubscriptions::SubscriptionUsage::BudgetCaps::UserOverrideType],
          null: true,
          description: 'Updated user budget cap overrides.'

        MAX_OVERRIDES = 200

        def resolve(overrides:, namespace_path: nil, organization_id: nil)
          validate_overrides_limit!(overrides)

          target = resolve_target(namespace_path, organization_id)
          authorize_mutation!(target)
          check_usage_rate_limit!(target.namespace)

          cdot_overrides = prepare_overrides(overrides, target)

          client = build_subscription_usage_client(target)
          result = client.upsert_user_budget_cap_overrides(
            overrides: cdot_overrides
          )

          if result[:success]
            policy_subject = target.organization || build_subscription_usage(target, client)

            {
              user_overrides: wrap_overrides(
                result[:userBudgetCapOverrides], policy_subject
              ),
              errors: []
            }
          else
            { user_overrides: nil, errors: result[:errors] }
          end
        end

        private

        def validate_overrides_limit!(overrides)
          return if overrides.size <= MAX_OVERRIDES

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Cannot upsert more than #{MAX_OVERRIDES} overrides at once"
        end

        def prepare_overrides(overrides, target)
          ids_by_username = resolve_usernames!(overrides)

          identifiers_by_id = {}
          user_ids = overrides.map do |o|
            id = o[:user_id] ? o[:user_id].model_id.to_i : ids_by_username.fetch(o[:username].downcase)
            identifiers_by_id[id] ||= o[:user_id]&.to_s || o[:username]
            id
          end

          cdot_overrides = overrides.zip(user_ids).map do |o, id|
            {
              entityId: id.to_s,
              capAmount: o[:cap],
              enabled: o[:enabled]
            }
          end

          unique_ids = user_ids.uniq
          validate_user_ids!(unique_ids)

          if target.organization
            validate_organization_membership!(unique_ids, target.organization, identifiers_by_id)
          elsif target.namespace
            validate_namespace_membership!(unique_ids, target.namespace, identifiers_by_id)
          end

          cdot_overrides
        end

        def resolve_usernames!(overrides)
          usernames = overrides.filter_map { |o| o[:username] }.uniq
          return {} if usernames.empty?

          ids_by_username = User.by_username(usernames)
            .select(:id, :username)
            .index_by { |user| user.username.downcase }
            .transform_values(&:id)

          missing = usernames.reject { |username| ids_by_username.key?(username.downcase) }
          return ids_by_username if missing.empty?

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Users not found: #{missing.join(', ')}"
        end

        def validate_user_ids!(user_ids)
          return if user_ids.empty?

          existing_ids = User.id_in(user_ids).limit(user_ids.size).select(:id).map(&:id)
          return if existing_ids.size == user_ids.size

          missing_ids = user_ids - existing_ids
          missing_gids = missing_ids.map do |id|
            ::Gitlab::GlobalId.as_global_id(id, model_name: 'User').to_s
          end

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Users not found: #{missing_gids.join(', ')}"
        end

        def validate_namespace_membership!(user_ids, namespace, identifiers_by_id)
          eligible_ids = namespace.gitlab_duo_eligible_user_ids
          non_member_ids = user_ids.reject { |id| eligible_ids.include?(id) }
          return if non_member_ids.empty?

          non_members = non_member_ids.map { |id| identifiers_by_id.fetch(id) }

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Users are not part of the namespace: #{non_members.join(', ')}"
        end

        def validate_organization_membership!(user_ids, organization, identifiers_by_id)
          member_ids = organization.users.id_in(user_ids).select(:id).map(&:id)
          non_member_ids = user_ids - member_ids
          return if non_member_ids.empty?

          non_members = non_member_ids.map { |id| identifiers_by_id.fetch(id) }

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Users are not part of the organization: #{non_members.join(', ')}"
        end

        def build_subscription_usage(target, client)
          ::GitlabSubscriptions::SubscriptionUsage.new(
            subscription_target: target.type,
            subscription_usage_client: client,
            namespace: target.namespace
          )
        end

        def wrap_overrides(overrides, policy_subject)
          Array.wrap(overrides).map do |node|
            ::GitlabSubscriptions::SubscriptionsUsage::BudgetCaps::UserOverride.new(
              entity_id: node[:entityId],
              cap: node[:cap],
              cap_enabled: node[:capEnabled],
              created_at: node[:createdAt],
              updated_at: node[:updatedAt],
              declarative_policy_subject: policy_subject
            )
          end
        end
      end
    end
  end
end
