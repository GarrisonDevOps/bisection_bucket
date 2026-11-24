# frozen_string_literal: true

module Analytics
  module CustomDashboards
    # A request is scoped to one organization (Cells), so dashboards are resolved
    # through the current organization rather than by bare ID.
    module ScopedToCurrentOrganization
      private

      def resolve_current_organization
        context[:current_organization] || ::Current.organization
      end

      # A request is scoped to one organization, so an explicit ID may only name the current one.
      def find_current_organization(organization_id)
        organization = resolve_current_organization
        return organization unless organization_id
        return unless organization

        organization if organization_id.model_id == organization.id.to_s
      end

      def find_current_organization_dashboard(id)
        organization = resolve_current_organization
        return unless organization

        gid = GitlabSchema.parse_gid(id, expected_type: ::Analytics::CustomDashboards::Dashboard)
        organization.custom_dashboards.find_by_id(gid.model_id)
      end
    end
  end
end
