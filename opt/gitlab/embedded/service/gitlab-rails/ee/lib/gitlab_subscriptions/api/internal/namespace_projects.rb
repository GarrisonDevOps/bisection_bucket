# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class NamespaceProjects < ::API::Base
        include ::API::PaginationParams

        feature_category :subscription_management
        urgency :low

        namespace :internal do
          namespace :gitlab_subscriptions do
            resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
              before do
                @namespace = find_namespace(params[:id])

                not_found!('Namespace') unless @namespace.present?
              end

              desc 'Returns the projects of a namespace (including subgroups), with license data included' do
                detail 'Used by CustomersDot to check OSS program compliance for a namespace, avoiding ' \
                  'one API call per project to fetch license data.'
                success Entities::Internal::ProjectWithLicense
                is_array true
                failure [
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[namespace_projects]
              end
              params do
                requires :id, types: [String, Integer],
                  desc: 'The ID or URL-encoded path of the namespace'
                use :pagination
              end
              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              get ":id/projects" do
                projects = ::Namespaces::ProjectsFinder.new(
                  namespace: @namespace,
                  params: { include_subgroups: true, sort: 'id_asc' }
                ).execute.include_project_feature

                present paginate(projects), with: Entities::Internal::ProjectWithLicense
              end
            end
          end
        end
      end
    end
  end
end
