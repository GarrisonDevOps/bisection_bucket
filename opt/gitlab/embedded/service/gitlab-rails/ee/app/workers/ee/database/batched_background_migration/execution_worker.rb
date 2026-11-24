# frozen_string_literal: true

module EE
  module Database # rubocop:disable Gitlab/BoundedContexts -- Extends the existing FOSS module
    module BatchedBackgroundMigration
      module ExecutionWorker
        extend ActiveSupport::Concern

        prepended do
          prepend ::Geo::SkipSecondary
        end
      end
    end
  end
end
