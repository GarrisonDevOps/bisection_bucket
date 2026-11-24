# frozen_string_literal: true

module Types
  module Search
    class SearchTypeEnum < BaseEnum
      graphql_name 'SearchType'
      description 'Type of search'

      value 'BASIC', value: 'basic', description: 'Basic search.'
      value 'ADVANCED', value: 'advanced', description: 'Advanced search.'
      value 'ZOEKT', value: 'zoekt', description: 'Exact code search.'
    end
  end
end
