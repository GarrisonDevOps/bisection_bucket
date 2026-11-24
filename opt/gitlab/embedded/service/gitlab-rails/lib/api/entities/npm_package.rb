# frozen_string_literal: true

module API
  module Entities
    class NpmPackage < Grape::Entity
      expose :name, documentation: { type: 'String', example: 'my_package' }
      expose :versions,
        documentation: {
          type: 'object',
          example: {
            "1.0.0" => {
              "name" => "my_package",
              "version" => "1.0.0",
              "dist" => { "shasum" => "12345", "tarball" => "https://..." }
            }
          }
        }
      expose :time,
        expose_nil: false,
        documentation: {
          type: 'object',
          example: {
            "created" => "2026-01-12T08:41:01.956Z",
            "modified" => "2026-01-15T10:36:46.866Z",
            "1.0.0" => "2026-01-12T08:41:01.956Z",
            "1.0.1" => "2026-01-15T10:36:46.866Z"
          }
        }
      expose :dist_tags, as: 'dist-tags', documentation: { type: 'object', example: { "latest" => "1.0.1" } }
    end
  end
end
