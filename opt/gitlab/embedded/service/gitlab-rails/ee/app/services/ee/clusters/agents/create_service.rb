# frozen_string_literal: true

module EE
  module Clusters
    module Agents
      module CreateService
        def execute
          super.tap do |response|
            if response.success?
              send_success_audit_event(response)
            else
              send_failure_audit_event(response)
            end
          end
        end

        private

        def send_success_audit_event(response)
          cluster_agent = response[:cluster_agent]

          audit_context = {
            name: 'cluster_agent_created',
            author: current_user,
            scope: project,
            target: cluster_agent,
            message: "Created cluster agent '#{cluster_agent.name}' with id #{cluster_agent.id}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def send_failure_audit_event(response)
          audit_context = {
            name: 'cluster_agent_create_failed',
            author: current_user,
            scope: project,
            target: project,
            message: "Attempted to create cluster agent '#{params[:name]}' " \
              "but failed with message: #{response[:message]}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
