# frozen_string_literal: true

module Packages
  class CreateAuditEventsService < ::Packages::AuditEventsBaseService
    include ::Gitlab::Utils::StrongMemoize

    def initialize(packages, current_user: nil, event_name: 'package_registry_package_deleted')
      @packages = packages
      @current_user = current_user
      @event_name = event_name
    end

    def execute
      super do
        ::Gitlab::Audit::Auditor.audit(initial_audit_context) do
          eligible_packages.each { |pkg| send_event(pkg) }
        end
      end
    end

    private

    attr_reader :packages, :current_user, :event_name

    def audit_events_enabled?
      eligible_packages.any?
    end

    def eligible_packages
      packages.select { |pkg| package_settings[pkg.project.namespace_id] }
    end
    strong_memoize_attr :eligible_packages

    def package_settings
      ::Namespace::PackageSetting
        .select(:namespace_id)
        .namespace_id_in(packages.map { |pkg| pkg.project.namespace_id })
        .with_audit_events_enabled
        .index_by(&:namespace_id)
    end
    strong_memoize_attr :package_settings

    def initial_audit_context
      {
        name: event_name,
        author: current_user || ::Gitlab::Audit::NullAuthor.new,
        scope: ::Group.new,
        target: ::Gitlab::Audit::NullTarget.new,
        additional_details: { auth_token_type: }
      }
    end

    def send_event(package)
      scope = groups[package.project.namespace_id] || package.project

      package.run_after_commit_or_now do
        event = {
          scope: scope,
          target: self,
          target_details: "#{project.full_path}/#{name}-#{version}",
          message: "#{package_type.humanize} package deleted"
        }
        push_audit_event(event, after_commit: false)
      end
    end

    def groups
      ::Group
        .select(:id)
        .include_route
        .id_in(eligible_packages.map { |pkg| pkg.project.namespace_id })
        .index_by(&:id)
    end
    strong_memoize_attr :groups
  end
end
