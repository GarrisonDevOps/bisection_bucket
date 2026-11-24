# frozen_string_literal: true

module Geo
  class DesignManagementRepositoryRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :design_management_repository, class_name: 'DesignManagement::Repository'

    def self.model_class
      ::DesignManagement::Repository
    end

    def self.model_foreign_key
      :design_management_repository_id
    end
  end
end
