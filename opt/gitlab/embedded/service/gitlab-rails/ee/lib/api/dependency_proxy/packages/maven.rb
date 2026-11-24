# frozen_string_literal: true

module API
  class DependencyProxy
    module Packages
      class Maven < ::API::Base
        include ::API::Concerns::DependencyProxy::PackagesHelpers

        helpers ::API::Helpers::Packages::Maven
        helpers ::API::Helpers::Packages::Maven::BasicAuthHelpers
        helpers ::API::Helpers::Packages::Maven::ApiErrorFormatter

        content_type :md5, 'text/plain'
        content_type :sha1, 'text/plain'
        content_type :binary, 'application/octet-stream'

        DIGESTS_FORMATS = %w[sha1 md5].freeze

        helpers do
          delegate :url_from_maven_upstream, :headers_from_maven_upstream, to: :dependency_proxy_setting
          alias_method :remote_url_headers, :headers_from_maven_upstream

          def project
            authorized_user_project(action: :read_package)
          end

          def remote_package_file_url
            url_from_maven_upstream(path: declared_params[:path], file_name: declared_params[:file_name])
          end

          def respond_digest(digest)
            track_file_pulled_event(from_cache: true)
            digest
          end

          def upload_method
            'PUT'
          end

          def upload_url
            url = api_v4_projects_packages_maven_path_path(
              {
                id: dependency_proxy_setting.project_id,
                path: declared_params[:path],
                file_name: declared_params[:file_name]
              },
              true
            )
            expose_url(url)
          end

          # if the endpoint was accessed by custom http headers: nothing to do.
          # if basic auth was used: transpose credentials from basic auth to custom http headers
          def upload_headers
            return {} unless has_basic_credentials?(current_request)

            header_name = case token_from_namespace_inheritable
                          when PersonalAccessToken
                            'Private-Token'
                          when DeployToken
                            'Deploy-Token'
                          when ::Ci::Build
                            ::Gitlab::Auth::CI_JOB_USER
                          end
            return {} unless header_name

            _, token = user_name_and_password(current_request)
            { header_name => token }
          end

          def wrap_error_response
            unauthorized_or! { yield }
          end

          def present_package_file!(package_file)
            download_package_file!(
              package_file,
              extra_response_headers: EXTRA_RESPONSE_HEADERS,
              extra_send_url_params: {
                restrict_forwarded_response_headers: {
                  enabled: true,
                  allow_list: ALLOWED_HEADERS
                }
              }
            )
          end
        end

        authenticate_with do |accept|
          accept.token_types(:personal_access_token).sent_through(:http_private_token_header)
          accept.token_types(:deploy_token).sent_through(:http_deploy_token_header)
          accept.token_types(:job_token).sent_through(:http_job_token_header)
          accept.token_types(
            :personal_access_token_with_username,
            :deploy_token_with_username,
            :job_token_with_username
          ).sent_through(:http_basic_auth)
        end

        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
        end
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Proxy the download of a maven package file at a project level' do
            detail 'This feature was introduced in GitLab 16.2'
            success [
              { code: 200 }
            ]
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not Found' }
            ]
            tags %w[dependency_proxy]
            produces %w[application/octet-stream]
          end
          params do
            requires :file_name, type: String, desc: 'The package file name'
            use :path_and_file_name
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :download_maven_package_file, boundary_type: :project
          get ':id/dependency_proxy/packages/maven/*path/:file_name',
            requirements: { file_name: ::API::NO_SLASH_URL_PART_REGEX } do
            file_name, format = extract_format(params[:file_name])
            package = fetch_package(project: project, file_name: file_name)
            package_file = ::Packages::PackageFileFinder.new(package, file_name).execute if package

            handle(package_file) do |callbacks|
              callbacks.skip_upload = -> { format.in?(DIGESTS_FORMATS) }
              callbacks.before_respond_with = -> do
                respond_digest(package_file["file_#{format}"]) if format.in?(DIGESTS_FORMATS)
              end
            end
          end
        end
      end
    end
  end
end
