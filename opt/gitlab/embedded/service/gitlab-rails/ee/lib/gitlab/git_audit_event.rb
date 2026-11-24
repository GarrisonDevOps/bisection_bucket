# frozen_string_literal: true

module Gitlab
  class GitAuditEvent # rubocop:disable Gitlab/NamespacedClass
    attr_reader :project, :author, :request

    def initialize(player, project, request = nil)
      @project = project
      @author = player.is_a?(::API::Support::GitAccessActor) ? player.resolved_identity : player
      @request = request
    end

    def enabled?
      author.present? && project.present?
    end

    def send_audit_event(message)
      return if author.blank? || project.blank?

      ip_address = message.delete(:ip_address) if message.is_a?(Hash)

      additional_details = {}
      additional_details[:user_agent] = Gitlab::Audit::Sanitizer.sanitize_user_agent(request.user_agent) if request

      audit_context = {
        name: 'repository_git_operation',
        stream_only: true,
        author: author,
        scope: project,
        target: project,
        message: message,
        additional_details: additional_details
      }

      audit_context[:ip_address] = ip_address if ip_address

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end
  end
end
