# frozen_string_literal: true

module Types
  module Analytics
    module Dora
      # rubocop: disable Graphql/AuthorizeTypes -- authorized in parent
      class GroupDoraType < DoraType
        graphql_name 'GroupDora'
        description 'All information related to group DORA metrics.'

        field :projects, Types::ProjectType.connection_type, null: false,
          description: 'Projects within this group with at least 1 DORA metric for given period.',
          resolver: ::Resolvers::Analytics::Dora::DoraProjectsResolver
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
