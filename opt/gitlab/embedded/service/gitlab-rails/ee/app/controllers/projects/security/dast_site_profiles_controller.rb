# frozen_string_literal: true

module Projects
  module Security
    class DastSiteProfilesController < Projects::ApplicationController
      include SecurityAndCompliancePermissions
      include API::Helpers::GraphqlHelpers

      before_action do
        authorize_read_on_demand_dast_scan!
      end

      feature_category :dynamic_application_security_testing
      urgency :low

      def new; end

      def edit
        id = params.permit(:id)[:id]

        global_id = Gitlab::GlobalId.as_global_id(id, model_name: 'DastSiteProfile')

        site_profile = DastSiteProfile.find(id)
        return render_403 unless site_profile.can_edit_profile?(current_user)

        query = %(
          {
            project(fullPath: "#{project.full_path}") {
              dastSiteProfile(id: "#{global_id}") {
                id
                name: profileName
                targetUrl
                targetType
                excludedUrls
                requestHeaders
                auth { enabled url username usernameField password passwordField submitField }
                referencedInSecurityPolicies
                scanMethod
                optionalVariables
              }
            }
          }
        )

        @site_profile = run_graphql!(
          query: query,
          context: { current_user: current_user },
          transform: ->(result) { result.dig('data', 'project', 'dastSiteProfile') }
        )

        render_404 unless @site_profile
      end
    end
  end
end
