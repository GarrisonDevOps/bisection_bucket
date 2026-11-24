# frozen_string_literal: true

module API
  module Entities
    module EpicBoards
      class ListDetails < Entities::EpicBoards::List
        expose :collapsed, documentation: { type: 'Boolean', example: false }

        def collapsed
          object.collapsed?(options[:current_user])
        end
      end
    end
  end
end
