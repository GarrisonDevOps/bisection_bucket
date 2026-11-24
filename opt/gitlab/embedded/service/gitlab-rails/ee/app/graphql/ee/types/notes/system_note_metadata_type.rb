# frozen_string_literal: true

module EE
  module Types
    module Notes
      module SystemNoteMetadataType
        extend ActiveSupport::Concern

        prepended do
          field :description_diff_available, GraphQL::Types::Boolean,
            null: false,
            resolver_method: :description_diff_available?,
            description: 'Indicates if a diff with the previous description version is available. ' \
              'Use `descriptionVersion` to fetch its details.'
        end

        def description_diff_available?
          version = object.description_version
          return false if version.nil? || version.deleted?

          version.description_diffs_available?
        end
      end
    end
  end
end
