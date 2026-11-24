# frozen_string_literal: true

module Geo
  class SnippetRepositoryState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :snippet_repository,
      inverse_of: :snippet_repository_state

    validates :verification_state, :snippet_repository, presence: true
  end
end
