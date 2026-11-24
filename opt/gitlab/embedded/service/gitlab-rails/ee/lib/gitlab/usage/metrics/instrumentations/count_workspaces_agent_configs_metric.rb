# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountWorkspacesAgentConfigsMetric < DatabaseMetric
          operation :distinct_count, column: :cluster_agent_id

          # TODO: Do we only want to consider agents that have successfully connected?
          relation { RemoteDevelopment::WorkspacesAgentConfig }

          start { RemoteDevelopment::WorkspacesAgentConfig.minimum(:cluster_agent_id) }
          finish { RemoteDevelopment::WorkspacesAgentConfig.maximum(:cluster_agent_id) }
        end
      end
    end
  end
end
