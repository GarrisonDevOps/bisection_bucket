# frozen_string_literal: true

module Types
  module Security
    class TrackedRefStateEnum < BaseEnum
      graphql_name 'SecurityTrackedRefState'
      description 'State of security tracked ref.'

      value 'TRACKED', 'Ref is being tracked for vulnerabilities.'
      value 'UNTRACKED', 'Ref is not being tracked for vulnerabilities.'
    end
  end
end
