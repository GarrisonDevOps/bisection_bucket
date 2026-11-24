# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Iteration < Grape::Entity
          expose :iteration,
            using: ::API::Entities::Iteration,
            documentation: {
              type: 'Entities::Iteration',
              desc: 'Iteration the work item is assigned to. Null if none is assigned or the current user ' \
                'cannot view it.'
            },
            expose_nil: true do |feature, options|
            iteration = feature.iteration
            next unless iteration && ::Ability.allowed?(options[:current_user], :read_iteration, iteration)

            iteration
          end
        end
      end
    end
  end
end
