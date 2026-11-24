# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class MarkCvsProjectsAsVulnerable < AbstractTask
        def execute
          new_vulnerable_projects.each { |project| project.project_setting.mark_as_vulnerable! }
        end

        private

        def new_vulnerable_projects
          unique_projects.select { |project| !project.project_setting&.has_vulnerabilities? }
        end

        def unique_projects
          finding_maps.map(&:project).uniq
        end
      end
    end
  end
end
