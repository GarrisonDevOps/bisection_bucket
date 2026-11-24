# frozen_string_literal: true

module EE
  module Types
    module Repository
      module BlobType
        extend ActiveSupport::Concern
        include GrapePathHelpers::NamedRouteMatcher
        include ::EE::BlobHelper # rubocop: disable Cop/InjectEnterpriseEditionModule -- Using direct include for BlobHelper to access instance methods

        prepended do
          field :code_owners, [::Types::UserType],
            null: true,
            description: 'List of code owners for the blob.',
            calls_gitaly: true

          field :show_duo_workflow_action, GraphQL::Types::Boolean, null: true,
            description: 'Indicator to show Duo Agent Platform action.'
        end

        def show_duo_workflow_action
          show_duo_workflow_action?(object)
        end
      end
    end
  end
end
