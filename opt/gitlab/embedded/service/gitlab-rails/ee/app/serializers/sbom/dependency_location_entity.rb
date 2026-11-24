# frozen_string_literal: true

module Sbom
  class DependencyLocationEntity < Grape::Entity
    include RequestAwareEntity

    class LocationEntity < Grape::Entity
      expose :blob_path, :path, :top_level
    end

    class ProjectEntity < Grape::Entity
      expose :name
      expose :full_path
    end

    expose :location, using: LocationEntity
    expose :has_dependency_paths?, as: :has_dependency_paths
    expose :project, using: ProjectEntity
    expose :id, as: :occurrence_id
  end
end
