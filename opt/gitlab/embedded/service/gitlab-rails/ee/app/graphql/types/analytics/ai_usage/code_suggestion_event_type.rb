# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      # rubocop: disable Graphql/AuthorizeTypes -- authorized with parent object type
      class CodeSuggestionEventType < AiUsageEventType
        graphql_name 'CodeSuggestionEvent'

        field :language,
          GraphQL::Types::String,
          null: true,
          description: 'Programming language in the context of the suggestion.'

        field :suggestion_size,
          GraphQL::Types::String,
          null: true,
          description: 'Size of the code suggestion measured in lines of code.'

        field :unique_tracking_id,
          GraphQL::Types::String,
          null: true,
          description: 'Unique tracking number of sequence of events for one suggestion.'

        def language
          extras && extras['language']
        end

        def suggestion_size
          extras && extras['suggestion_size']
        end

        def unique_tracking_id
          extras && extras['unique_tracking_id']
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
