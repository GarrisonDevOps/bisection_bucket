# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountUsersCreatingCiBuildsMetric < CountCreatingCiBuildMetric
          relation { ::Ci::Build }

          operation :distinct_count, column: :user_id
          cache_start_and_finish_as :count_users_creating_ci_builds

          start { ::User.minimum(:id) }
          finish { ::User.maximum(:id) }
        end
      end
    end
  end
end
