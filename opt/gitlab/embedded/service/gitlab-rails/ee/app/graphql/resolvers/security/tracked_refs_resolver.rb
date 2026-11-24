# frozen_string_literal: true

module Resolvers
  module Security
    class TrackedRefsResolver < BaseResolver
      type Types::Security::TrackedRefType.connection_type, null: true

      authorize :read_security_resource

      description 'Security tracked refs for vulnerability tracking'

      argument :state, Types::Security::TrackedRefStateEnum, required: false,
        description: 'Filter by tracking state. Values: "TRACKED", "UNTRACKED". Returns all refs if not specified.'

      def resolve(state: nil)
        ::Security::TrackedRefsFinder.new(object, current_user, { state: state }).execute
      end
    end
  end
end
