# frozen_string_literal: true

module EE
  module VerifyPagesDomainService
    extend ::Gitlab::Utils::Override

    override :after_successful_verification
    def after_successful_verification
      super

      ::Groups::EnterpriseUsers::BulkAssociateByDomainWorker.perform_async(domain.id)
    end

    override :log_audit_event
    def log_audit_event(type)
      project = domain.project
      audit_context = {
        name: "pages_domain_#{type}",
        author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
        scope: project,
        target: project,
        target_details: domain.domain,
        message: "Domain #{type.to_s.humanize(capitalize: false)} - #{domain.domain}"
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end
  end
end
