# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class ProjectWithLicense < Grape::Entity
          expose :id, documentation: { type: 'Integer', example: 1 }
          expose :path_with_namespace, documentation: { type: 'String', example: 'namespace1/project1' }
          expose :web_url, documentation: { type: 'String', example: 'https://gitlab.example.com/namespace1/project1' }
          expose :visibility, documentation: { type: 'String', example: 'public' }
          expose :empty_repo?, as: :empty_repo, documentation: { type: 'Boolean' }
          expose :wiki_enabled?, as: :wiki_enabled, documentation: { type: 'Boolean' }

          # License detection requires a repository (Gitaly) call, so it's only performed for
          # projects where it's actually needed: public projects with content. Private projects
          # are excluded from OSS-compliance license checks by callers regardless of license
          # status, and empty projects (including wiki-only ones) have no repository content to
          # detect a license from.
          expose :license, using: ::API::Entities::LicenseBasic,
            if: ->(project, _) { project.public? && !project.empty_repo? },
            documentation: { type: 'LicenseBasic' } do |project|
            project.repository.license
          end
        end
      end
    end
  end
end
