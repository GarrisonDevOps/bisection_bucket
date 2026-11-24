# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    class TrialUsageResolver < BaseResolver
      include ::GitlabSubscriptions::UsageRateLimitable
      include ::GitlabSubscriptions::UsageTargetResolvable

      type Types::GitlabSubscriptions::TrialUsageType, null: true

      argument :namespace_path, GraphQL::Types::ID,
        required: false,
        description: "Path of the top-level namespace. Leave it blank if querying the instance subscription."

      argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
        required: false,
        prepare: ->(global_id, _ctx) { global_id&.model_id },
        experiment: { milestone: '19.6' },
        description: 'Global ID of the organization billed through a nominated group.'

      validates mutually_exclusive: [:namespace_path, :organization_id]

      def resolve(**args)
        usage_target = resolve_usage_target!(args)

        check_usage_rate_limit!(usage_target.namespace)

        license_key = License.current&.data if usage_target.subscription_target == :instance

        subscription_usage_client = ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(**{
          license_key: license_key,
          namespace_id: usage_target.namespace&.id
        }.compact)

        context[:subscription_usage_client] = subscription_usage_client

        ::GitlabSubscriptions::TrialsUsage::Base.new(
          subscription_target: usage_target.subscription_target,
          namespace: usage_target.namespace,
          organization: usage_target.organization,
          subscription_usage_client: subscription_usage_client
        )
      end

      private

      def authorize!(subscription_target, namespace)
        return authorize_for_instance! if subscription_target == :instance

        raise_resource_not_available_error! unless namespace

        unless namespace.root? && namespace.group_namespace?
          raise_resource_not_available_error!("Trial usage can only be queried on a root namespace")
        end

        raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_subscription_usage, namespace)
      end
    end
  end
end
