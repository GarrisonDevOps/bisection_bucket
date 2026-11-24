# frozen_string_literal: true

module GitlabSubscriptions
  module UsageTargetResolvable
    extend ActiveSupport::Concern
    include Gitlab::Graphql::Authorize::AuthorizeResource

    UsageTarget = Data.define(:subscription_target, :organization, :namespace)

    private

    def resolve_usage_target!(args)
      subscription_target = args.values_at(:namespace_path, :organization_id).any? ? :namespace : :instance
      organization = find_organization(args[:organization_id])
      namespace = organization ? organization.billing_namespace : find_namespace(args[:namespace_path])

      if args[:organization_id]
        authorize_for_organization!(organization)
      else
        authorize!(subscription_target, namespace)
      end

      UsageTarget.new(subscription_target:, organization:, namespace:)
    end

    def find_namespace(namespace_path)
      return unless namespace_path

      Namespace.find_by_full_path(namespace_path)
    end

    def find_organization(organization_id)
      return unless organization_id

      ::Organizations::Organization.find_by_id(organization_id)
    end

    def authorize_for_instance!
      raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_subscription_usage)
    end

    # The policy also requires organization_billing and a billing namespace.
    def authorize_for_organization!(organization)
      return if organization && Ability.allowed?(current_user, :read_subscription_usage, organization)

      raise_resource_not_available_error!
    end
  end
end
