# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Persistence
        class WorkspacesToBeReturnedUpdater
          # @param [Hash] context
          # @return [Hash]
          def self.update(context)
            context => {
              agent: agent, # Skip type checking so we can use fast_spec_helper in the unit test spec
              workspaces_to_be_returned: Array => workspaces_to_be_returned,
            }

            # Update the responded_to_agent_at at this point, after we have already done all the calculations
            # related to state. Do it as a single query, so that they will all have the same timestamp.

            workspaces_to_be_returned_ids = workspaces_to_be_returned.map(&:id)

            agent.workspaces.id_in(workspaces_to_be_returned_ids).touch_all(:responded_to_agent_at)
            agent.workspaces.id_in(workspaces_to_be_returned_ids)
                 .forced_to_include_all_resources.update_all(force_include_all_resources: false)
            context
          end
        end
      end
    end
  end
end
