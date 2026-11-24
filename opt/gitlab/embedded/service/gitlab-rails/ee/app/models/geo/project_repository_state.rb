# frozen_string_literal: true

module Geo
  class ProjectRepositoryState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :project_repository, inverse_of: :project_repository_state
    belongs_to :project

    validates :verification_state, :project_repository, presence: true
    validates :project_repository, uniqueness: true

    before_validation :set_project_from_project_repository

    private

    def set_project_from_project_repository
      self.project_id ||= project_repository&.project_id
    end
  end
end
