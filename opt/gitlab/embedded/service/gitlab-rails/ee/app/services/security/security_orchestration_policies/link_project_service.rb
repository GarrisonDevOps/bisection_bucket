# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class LinkProjectService < BaseProjectPolicyService
      def initialize(project:, security_policy:, action:)
        super(project: project, security_policy: security_policy)

        @action = action
      end

      def execute
        case @action
        when :link then link_policy
        when :unlink then unlink_policy
        else raise "unsupported action: #{@action}"
        end
      end
    end
  end
end
