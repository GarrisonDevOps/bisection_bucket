# frozen_string_literal: true

module Types
  module Analytics
    module ValueStreamDashboard
      class ProjectMetricEnum < BaseEnum
        graphql_name 'ValueStreamDashboardProjectLevelMetric'
        description 'Possible identifier types for project-level measurement'

        CONTRIBUTOR_METRIC = 'contributors'

        value 'ISSUES', 'Issue count.', value: 'issues'
        value 'MERGE_REQUESTS', 'Merge request count.', value: 'merge_requests'
        value 'PIPELINES', 'Pipeline count.', value: 'pipelines'

        text = 'Contributor count. EXPERIMENTAL: Only available on the SaaS ' \
          'version of GitLab when the ClickHouse database backend is enabled.'
        value 'CONTRIBUTORS', value: CONTRIBUTOR_METRIC, description: text
      end
    end
  end
end
