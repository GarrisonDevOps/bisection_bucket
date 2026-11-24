# frozen_string_literal: true

module Packages
  class CreateAuditEventService < ::Packages::AuditEventsBaseService
    delegate :project, :creator, to: :package, private: true

    def initialize(package, current_user: nil, event_name: 'package_registry_package_published')
      @package = package
      @current_user = current_user
      @event_name = event_name
    end

    def execute
      super do
        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end

    private

    attr_reader :package, :current_user, :event_name

    def audit_events_enabled?
      ::Namespace::PackageSetting
        .namespace_id_in(project.namespace_id)
        .with_audit_events_enabled
        .exists?
    end

    def audit_context
      {
        name: event_name,
        author: author,
        scope: project.group || project,
        target: package,
        target_details: target_details,
        message: audit_message,
        additional_details: { auth_token_type: }
      }
    end

    def author
      current_user || creator || ::Gitlab::Audit::DeployTokenAuthor.new
    end

    def target_details
      "#{project.full_path}/#{package.name}-#{package.version}"
    end

    def audit_message
      action = case event_name
               when 'package_registry_package_published'
                 'published'
               when 'package_registry_package_deleted'
                 'deleted'
               end

      "#{package.package_type.humanize} package #{action}"
    end

    def auth_token_type
      super || token_type_from_package_creator
    end

    def token_type_from_package_creator
      return 'DeployToken' unless creator
      return 'CiJobToken' if creator.from_ci_job_token?

      'PersonalAccessToken or CiJobToken'
    end
  end
end
