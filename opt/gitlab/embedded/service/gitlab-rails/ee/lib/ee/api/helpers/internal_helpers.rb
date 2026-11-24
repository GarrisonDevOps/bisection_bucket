# frozen_string_literal: true

module EE
  module API
    module Helpers
      module InternalHelpers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :access_checker_for
        def access_checker_for(actor, protocol)
          super.tap do |checker|
            checker.allowed_namespace_path = params[:namespace_path]
          end
        end

        override :send_git_audit_streaming_event
        def send_git_audit_streaming_event(msg)
          ::Gitlab::GitAuditEvent.new(actor, project, request).send_audit_event(msg)
        end

        override :need_git_audit_event?
        def need_git_audit_event?
          return true if super

          ::Gitlab::GitAuditEvent.new(actor, project).enabled?
        end
      end
    end
  end
end
