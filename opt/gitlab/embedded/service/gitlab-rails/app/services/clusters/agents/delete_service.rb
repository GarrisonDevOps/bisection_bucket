# frozen_string_literal: true

module Clusters
  module Agents
    class DeleteService < ::BaseContainerService
      def execute
        cluster_agent = params[:cluster_agent]

        return error_no_permissions unless Ability.allowed?(current_user, :admin_cluster, cluster_agent)

        if cluster_agent.destroy
          ServiceResponse.success
        else
          ServiceResponse.error(message: cluster_agent.errors.full_messages)
        end
      end

      private

      def error_no_permissions
        ServiceResponse.error(message: s_('ClusterAgent|You have insufficient permissions to delete this cluster agent'))
      end
    end
  end
end

Clusters::Agents::DeleteService.prepend_mod
