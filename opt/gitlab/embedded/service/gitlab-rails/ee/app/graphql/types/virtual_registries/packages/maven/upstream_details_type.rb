# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        # rubocop: disable Graphql/AuthorizeTypes -- authorization handled by parent UpstreamType
        class UpstreamDetailsType < ::Types::VirtualRegistries::Packages::Maven::UpstreamType
          graphql_name 'MavenUpstreamDetails'
          description 'Represents Maven upstream registry details.'

          field :registry_upstreams,
            [::Types::VirtualRegistries::Packages::Maven::RegistryUpstreamWithRegistryType],
            null: false,
            description: 'Represents the upstream registry for the upstream ' \
              'which contains the position data.',
            experiment: { milestone: '18.2' }

          field :cache_entries,
            ::Types::VirtualRegistries::Packages::Maven::Cache::EntryType.connection_type,
            null: true,
            description: 'Represents cache entries for the upstream.',
            resolver: ::Resolvers::VirtualRegistries::Packages::Maven::Cache::EntriesResolver,
            experiment: { milestone: '18.7' }

          field :allow_rules,
            [::Types::VirtualRegistries::Packages::Maven::Upstream::RuleType],
            null: false,
            experiment: { milestone: '18.10' },
            description: 'Allow rules for the upstream.'

          field :deny_rules,
            [::Types::VirtualRegistries::Packages::Maven::Upstream::RuleType],
            null: false,
            experiment: { milestone: '18.10' },
            description: 'Deny rules for the upstream.'
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
