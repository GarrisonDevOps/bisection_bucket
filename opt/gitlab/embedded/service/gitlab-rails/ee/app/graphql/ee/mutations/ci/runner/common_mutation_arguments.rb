# frozen_string_literal: true

module EE
  module Mutations
    module Ci
      module Runner
        module CommonMutationArguments
          extend ActiveSupport::Concern

          included do
            argument :public_projects_minutes_cost_factor, GraphQL::Types::Float,
              required: false,
              description: %q[Public projects' "compute cost factor" associated with the runner (GitLab.com only).],
              experiment: { milestone: '17.7' }

            argument :private_projects_minutes_cost_factor, GraphQL::Types::Float,
              required: false,
              description: %q[Private projects' "compute cost factor" associated with the runner (GitLab.com only).],
              experiment: { milestone: '17.7' }
          end
        end
      end
    end
  end
end
