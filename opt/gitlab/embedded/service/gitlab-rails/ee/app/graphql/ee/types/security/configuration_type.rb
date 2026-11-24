# frozen_string_literal: true

module EE
  module Types
    module Security
      module ConfigurationType
        extend ActiveSupport::Concern

        prepended do
          field :vulnerability_archive_export_path,
            GraphQL::Types::String,
            null: true,
            description: 'Path to export vulnerability archives via API.'
        end
      end
    end
  end
end
