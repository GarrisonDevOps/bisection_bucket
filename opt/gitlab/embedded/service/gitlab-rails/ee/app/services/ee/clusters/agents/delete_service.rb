# frozen_string_literal: true

module EE
  module Clusters
    module Agents
      module DeleteService
        def execute
          super.tap do |response|
            if response.success?
              send_success_audit_event
            else
              send_failure_audit_event(response)
            end
          end
        end

        private

        def send_success_audit_event
          cluster_agent = params[:cluster_agent]

          audit_context = {
            name: 'cluster_agent_deleted',
            author: current_user,
            scope: project,
            target: cluster_agent,
            message: "Deleted cluster agent '#{cluster_agent.name}' with id #{cluster_agent.id}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def send_failure_audit_event(response)
          cluster_agent = params[:cluster_agent]

          audit_context = {
            name: 'cluster_agent_delete_failed',
            author: current_user,
            scope: project,
            target: cluster_agent,
            message: "Attempted to delete cluster agent '#{cluster_agent.name}' but " \
              "failed with message: #{response.message}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
