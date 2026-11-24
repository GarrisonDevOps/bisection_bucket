# frozen_string_literal: true

module Resolvers
  module VirtualRegistries
    module Container
      class UpstreamsResolver < BaseResolver
        type ::Types::VirtualRegistries::Container::UpstreamType.connection_type, null: true

        alias_method :group, :object

        argument :upstream_name, GraphQL::Types::String,
          required: false,
          default_value: nil,
          description: 'Search upstreams by name.'

        def resolve(**args)
          return unless ::VirtualRegistries::Container.feature_enabled?(group)

          ::VirtualRegistries::UpstreamsFinder.new(
            upstream_class: ::VirtualRegistries::Container::Upstream,
            group: object,
            params: args.slice(:upstream_name)
          ).execute
        end

        private

        def authorized?(**_args)
          ::VirtualRegistries.user_has_access?(group, current_user)
        end
      end
    end
  end
end
