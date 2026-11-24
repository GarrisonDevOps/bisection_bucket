# frozen_string_literal: true

module Resolvers
  module VirtualRegistries
    module Cache
      # rubocop:disable Graphql/ResolverType -- the type is inherited from the parent class
      class EntriesResolver < BaseResolver
        include LooksAhead

        alias_method :upstream, :object

        argument :search, GraphQL::Types::String,
          required: false,
          default_value: nil,
          description: 'Search cache entries by relative path.'

        def resolve_with_lookahead(**args)
          return unless virtual_registry_available?

          apply_lookahead(
            ::VirtualRegistries::Cache::EntriesFinder.new(
              upstream: upstream,
              params: args.slice(:search)
            ).execute
          )
        end

        private

        def unconditional_includes
          [:group]
        end

        def authorized?(**_args)
          Ability.allowed?(current_user, :read_virtual_registry, upstream)
        end

        def virtual_registry_available?
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end
      end
      # rubocop:enable Graphql/ResolverType
    end
  end
end
