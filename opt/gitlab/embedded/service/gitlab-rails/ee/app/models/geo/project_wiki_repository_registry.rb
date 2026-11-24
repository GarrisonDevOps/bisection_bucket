# frozen_string_literal: true

module Geo
  class ProjectWikiRepositoryRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    extend ::Gitlab::Utils::Override

    belongs_to :project_wiki_repository, class_name: 'Projects::WikiRepository'

    validates :project_wiki_repository, presence: true, uniqueness: true

    delegate :project, :wiki_repository_state, to: :project_wiki_repository, allow_nil: true

    def self.model_class
      ::Projects::WikiRepository
    end

    def self.model_foreign_key
      :project_wiki_repository_id
    end
  end
end
