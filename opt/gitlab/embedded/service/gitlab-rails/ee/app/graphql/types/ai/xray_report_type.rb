# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- Authorized by parent node `:read_project` ability
    class XrayReportType < BaseObject
      graphql_name 'AiXrayReport'

      field :language, GraphQL::Types::String, null: false,
        description: 'Language of the x-ray report.',
        method: :lang
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
