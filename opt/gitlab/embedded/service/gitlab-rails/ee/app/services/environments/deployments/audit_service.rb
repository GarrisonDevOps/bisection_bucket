# frozen_string_literal: true

module Environments
  module Deployments
    class AuditService
      attr_reader :deployment

      def initialize(deployment)
        @deployment = deployment
      end

      def execute
        return unless deployment.environment.protected?

        create_audit_event(deployment)

        ServiceResponse.success
      end

      private

      def create_audit_event(deployment)
        audit_context = {
          name: "deployment_started",
          author: deployment.deployed_by,
          scope: deployment.project,
          target: deployment.environment,
          message: "Started deployment with IID: #{deployment.iid} and ID: #{deployment.id}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
