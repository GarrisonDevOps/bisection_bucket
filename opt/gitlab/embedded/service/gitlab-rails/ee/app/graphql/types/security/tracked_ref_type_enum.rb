# frozen_string_literal: true

module Types
  module Security
    class TrackedRefTypeEnum < BaseEnum
      graphql_name 'SecurityTrackedRefType'
      description 'Type of ref being tracked for security vulnerabilities.'

      value 'BRANCH', 'Branch ref.', value: :branch
      value 'TAG', 'Tag ref.', value: :tag
    end
  end
end
