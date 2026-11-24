# frozen_string_literal: true

module ComplianceManagement
  class UpdateDefaultFrameworkWorker
    include ApplicationWorker

    idempotent!
    data_consistency :always
    urgency :low
    feature_category :compliance_management

    def perform(_user_id, project_id, compliance_framework_id)
      project = Project.find(project_id)
      framework = ::ComplianceManagement::Framework.find(compliance_framework_id)

      return if project.compliance_management_frameworks.include?(framework)

      admin_bot = admin_bot_for_organization_id(project.organization_id)

      Gitlab::Auth::CurrentUserMode.bypass_session!(admin_bot.id) do
        result = ::ComplianceManagement::Frameworks::UpdateProjectService
          .new(project, admin_bot, [framework])
          .execute

        raise "Failed to assign default compliance framework: #{result.message}" unless result.success?

        # Service can silently skip the assignment if namespace traversal data
        # hasn't settled yet post-commit. Verify it actually happened and retry if not.
        unless project.compliance_management_frameworks.reset.include?(framework)
          raise "Default compliance framework was not assigned to project #{project.id}, will retry"
        end
      end
    rescue ActiveRecord::RecordNotFound => e
      Gitlab::ErrorTracking.track_and_raise_exception(e)
    end

    private

    def admin_bot_for_organization_id(organization_id)
      @admin_bots ||= {}
      @admin_bots[organization_id] ||= Users::Internal.in_organization(organization_id).admin_bot
    end
  end
end
