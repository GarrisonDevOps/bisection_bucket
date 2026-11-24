# frozen_string_literal: true

module Resolvers
  class PagesDeploymentsResolver < BaseResolver
    type Types::PagesDeploymentType.connection_type, null: true

    argument :active, GraphQL::Types::Boolean, required: false, description: "Filter by active or inactive state."
    argument :sort, Types::SortEnum, required: false, description: "Sort results."
    argument :versioned, GraphQL::Types::Boolean, required: false, description: "Filter deployments that are
versioned or unversioned."

    def resolve(**args)
      verify_rate_limit!

      Pages::DeploymentsFinder.new(object, args).execute
    end

    private

    # Runs per project, so a namespace query or aliased query pays for every resolution.
    def verify_rate_limit!
      return unless throttled?

      raise_resource_not_available_error!(::Gitlab::ApplicationRateLimiter.throttled_error_message)
    end

    def throttled?
      request = context[:request]

      if current_user
        key = :pages_deployments_api
        scope = { user: current_user }
      else
        # GraphqlChannel carries no request; the ActionCable worker sets IpAddressState.
        # A blank IP would collapse every anonymous caller into one labkit bucket.
        ip = request&.ip.presence || ::Gitlab::IpAddressState.current.presence
        return true unless ip

        key = :pages_deployments_api_unauthenticated
        scope = { ip: ip }
      end

      if request
        ::Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, key, scope: scope)
      else
        ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope)
      end
    end
  end
end
