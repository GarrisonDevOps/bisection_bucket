# frozen_string_literal: true

module Geo
  class PagesDeploymentRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :pages_deployment, class_name: 'PagesDeployment'

    def self.model_class
      ::PagesDeployment
    end

    def self.model_foreign_key
      :pages_deployment_id
    end
  end
end
