# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class BaseSecurityPolicyAuditEventService
      include Gitlab::Utils::StrongMemoize

      def initialize(policy_configuration)
        @policy_configuration = policy_configuration
      end

      private

      attr_reader :policy_configuration

      def policy_management_project
        policy_configuration.security_policy_management_project
      end
      strong_memoize_attr :policy_management_project

      def unknown_user
        Gitlab::Audit::DeletedAuthor.new(id: Gitlab::Audit::NullAuthor::UNKNOWN_USER_AUTHOR_ID, name: 'Unknown User')
      end

      def policy_audit_event_author
        policy_commit&.author || unknown_user
      end

      def policy_commit
        policy_configuration.latest_commit_before_configured_at
      end
    end
  end
end
