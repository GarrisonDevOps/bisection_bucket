# frozen_string_literal: true

module Types
  module Security
    class ProjectTrackedContextTypeEnum < BaseEnum
      graphql_name 'ProjectTrackedContext'
      description 'The context type of the tracked context'

      ::Security::ProjectTrackedContext.context_types.each_key do |type|
        value type.to_s.upcase, value: type.to_s, description: "#{type.to_s.titleize} type"
      end
    end
  end
end
