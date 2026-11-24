# frozen_string_literal: true

module Search
  module Zoekt
    module SearchableRepository
      extend ActiveSupport::Concern

      included do
        def use_zoekt?
          project&.use_zoekt?
        end

        def async_update_zoekt_index
          ::Search::Zoekt.with_project_context(project) do
            ::Search::Zoekt.index_async(project.id)
          end
        end
      end
    end
  end
end
