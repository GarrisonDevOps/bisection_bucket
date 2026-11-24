# frozen_string_literal: true

module Resolvers
  module VirtualRegistries
    module Packages
      module Maven
        class UpstreamsResolver < BaseResolver
          type ::Types::VirtualRegistries::Packages::Maven::UpstreamType.connection_type, null: true

          alias_method :group, :object

          argument :upstream_name, GraphQL::Types::String,
            required: false,
            default_value: nil,
            description: 'Search upstreams by name.'

          def resolve(**args)
            return unless ::VirtualRegistries::Packages::Maven.feature_enabled?(group)

            ::VirtualRegistries::UpstreamsFinder.new(
              upstream_class: ::VirtualRegistries::Packages::Maven::Upstream,
              group: group,
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
end
