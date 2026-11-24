# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsCreatingCiBuildsMetric < CountCreatingCiBuildMetric
          relation { ::Ci::Build }

          operation :distinct_count, column: :project_id
          cache_start_and_finish_as :count_projects_creating_ci_builds

          start { ::Project.minimum(:id) }
          finish { ::Project.maximum(:id) }
        end
      end
    end
  end
end
