# frozen_string_literal: true

module Types
  module Analytics
    module ValueStreamDashboard
      class MetricEnum < BaseEnum
        graphql_name 'ValueStreamDashboardMetric'
        description 'Possible identifier types for a measurement'

        CONTRIBUTOR_METRIC = 'contributors'

        value 'PROJECTS', 'Project count.', value: 'projects'
        value 'ISSUES', 'Issue count.', value: 'issues'
        value 'GROUPS', 'Group count.', value: 'groups'
        value 'MERGE_REQUESTS', 'Merge request count.', value: 'merge_requests'
        value 'PIPELINES', 'Pipeline count.', value: 'pipelines'
        value 'USERS', 'User count.', value: 'direct_members'

        text = 'Contributor count. EXPERIMENTAL: Only available on the SaaS ' \
               'version of GitLab when the ClickHouse database backend is enabled.'
        value 'CONTRIBUTORS', value: CONTRIBUTOR_METRIC, description: text
      end
    end
  end
end
