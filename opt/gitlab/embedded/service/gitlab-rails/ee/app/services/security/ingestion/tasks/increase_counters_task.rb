# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IncreaseCountersTask < AbstractTask
        def execute
          counts_by_projects.each do |project, new_vulnerability_count|
            project.security_statistics.increase_vulnerability_counter!(new_vulnerability_count)
          end
        end

        private

        def counts_by_projects
          new_finding_maps_by_project.transform_values(&:count)
        end

        def new_finding_maps_by_project
          new_finding_maps.group_by(&:project)
        end

        def new_finding_maps
          finding_maps.select(&:new_record)
        end
      end
    end
  end
end
