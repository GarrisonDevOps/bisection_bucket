# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class RecentSessionProjectsResolver < BaseResolver
        type [::Types::ProjectType], null: true

        def resolve
          ::Ai::DuoWorkflows::RecentSessionProjectsFinder.new(current_user: current_user).execute
        end
      end
    end
  end
end
