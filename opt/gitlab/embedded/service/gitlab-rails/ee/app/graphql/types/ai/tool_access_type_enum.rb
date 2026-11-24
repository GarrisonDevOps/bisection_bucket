# frozen_string_literal: true

module Types
  module Ai
    class ToolAccessTypeEnum < BaseEnum
      graphql_name 'AiToolAccessType'
      description 'Access type of an AI tool rule'

      value 'WEB_ACCESS', value: :web_access, description: 'Web surface access.'
      value 'LOCAL_ACCESS', value: :local_access, description: 'Local or IDE surface access.'
      value 'BACKGROUND_ACCESS', value: :background_access, description: 'Background-flow surface access.'
    end
  end
end
