# frozen_string_literal: true

module Types
  module Search
    class SearchLevelEnum < BaseEnum
      graphql_name 'SearchLevel'
      description 'Level of search'

      value 'PROJECT', value: 'project', description: 'Project search.'
      value 'GROUP', value: 'group', description: 'Group search.'
      value 'GLOBAL', value: 'global', description: 'Global search including all groups and projects.'
    end
  end
end
