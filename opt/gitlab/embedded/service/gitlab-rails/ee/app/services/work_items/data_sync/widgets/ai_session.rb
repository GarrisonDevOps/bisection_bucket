# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class AiSession < Base
        def after_save_commit
          # TODO: https://gitlab.com/gitlab-org/gitlab/-/work_items/595969
          # The relationship might change in the near future to a many to many relationship
        end
      end
    end
  end
end
