# frozen_string_literal: true

module API
  class DependencyProxy
    module Packages
      class Npm < ::API::Base
        # This block must come *before* ::API::Concerns::DependencyProxy::PackagesHelpers.
        # That concern will also use an after_validation block for business logic.
        after_validation do
          not_found! unless Feature.enabled?(:packages_dependency_proxy_npm, project)
        end

        include ::API::Concerns::DependencyProxy::PackagesHelpers

        authenticate_with do |accept|
          accept.token_types(:personal_access_token, :deploy_token, :job_token)
            .sent_through(:http_bearer_token)
        end

        helpers do
          include ::Gitlab::Utils::StrongMemoize

          delegate :npm_external_registry_basic_auth, :npm_external_registry_auth_token, :npm_external_registry_url,
            to: :dependency_proxy_setting

          def project
            user_project(action: :read_package)
          end

          def package
            ::Packages::Npm::Package
              .for_projects(project)
              .by_name_and_file_name(declared_params[:package_name], declared_params[:file_name])
          rescue ActiveRecord::RecordNotFound
            # we can't let the error bubble up. Instead, we need to return the nil value.
            nil
          end
          strong_memoize_attr :package

          def remote_package_file_url
            full_url = [
              npm_external_registry_url,
              declared_params[:package_name],
              '-',
              declared_params[:file_name]
            ].join('/')

            Addressable::URI.parse(full_url).to_s
          end

          def upload_url
            # TODO requires the upload endpoint
            # https://gitlab.com/gitlab-org/gitlab/-/issues/441267
          end

          def remote_url_headers
            return bearer_header(npm_external_registry_auth_token) if npm_external_registry_auth_token.present?
            return basic_header(npm_external_registry_basic_auth) if npm_external_registry_basic_auth.present?

            super
          end

          def basic_header(token)
            authorization_header("Basic #{token}")
          end

          def bearer_header(token)
            authorization_header("Bearer #{token}")
          end

          def authorization_header(value)
            { 'Authorization' => value }
          end

          def track_events?
            false
          end
        end

        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
        end
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          namespace ':id/dependency_proxy/packages/npm' do
            desc 'Proxy the download of a NPM package tarball' do
              detail 'This feature was introduced in 16.11'
              success [
                { code: 200 }
              ]
              failure [
                { code: 403, message: 'Forbidden' },
                { code: 404, message: 'Not Found' }
              ]
              tags %w[dependency_proxy]
            end
            params do
              requires :package_name, type: String, desc: 'Package name', regexp: Gitlab::Regex.npm_package_name_regex
              requires :file_name, type: String, desc: 'Package file name', file_path: true
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :download_npm_package, boundary_type: :project
            get '*package_name/-/*file_name', requirements: ::API::NO_FORMAT_SUFFIX_REQUIREMENT do
              package_file = ::Packages::PackageFileFinder.new(package, declared_params[:file_name]).execute! if package

              handle(package_file)
            end
          end
        end
      end
    end
  end
end
