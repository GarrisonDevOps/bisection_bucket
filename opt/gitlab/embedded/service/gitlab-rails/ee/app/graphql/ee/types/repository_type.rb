# frozen_string_literal: true

module EE
  module Types
    module RepositoryType
      extend ActiveSupport::Concern

      prepended do
        present_using RepositoryPresenter

        field :code_owners_path, GraphQL::Types::String,
          null: true,
          calls_gitaly: true,
          description: 'Path to CODEOWNERS file in a ref.' do
            argument :ref, GraphQL::Types::String, required: false, description: 'Name of the ref.'
          end

        field :diverged_from_upstream, GraphQL::Types::Boolean,
          null: true,
          calls_gitaly: true,
          complexity: 10,
          description: 'Indicates the branch has diverged from its pull mirror upstream. Premium and Ultimate only.' do
            argument :ref, GraphQL::Types::String, required: true, description: 'Name of the branch.'
          end

        field :validate_codeowner_file, Types::Repository::CodeOwnerValidationType,
          null: true,
          calls_gitaly: true,
          description: 'Shows linting errors in the CODEOWNER file of the repository.',
          resolver: EE::Resolvers::ValidateCodeownerFileResolver
      end
    end
  end
end
