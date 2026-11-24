# frozen_string_literal: true

module API
  module Scim
    class GroupScim < ::API::Base
      extend ::API::Scim::DiscoveryEndpoints

      # Group SCIM authenticates with a group SCIM token, not a user. Disable
      # the global Current.organization fallback so find_and_authenticate_group!
      # can assign the organization of the authenticated group instead.
      skip_global_organization_setup!

      feature_category :user_management

      prefix 'api/scim'
      version 'v2'
      content_type :json, 'application/scim+json'
      USER_ID_REQUIREMENTS = { id: /.+/ }.freeze

      params do
        requires :group, type: String, desc: 'The full path of the group'
      end
      namespace 'groups/:group' do
        params do
          requires :group, type: String, desc: 'The group path'
        end

        helpers ::EE::API::Helpers::ScimPagination
        helpers ::API::Helpers::ScimHelpers

        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def logger
            API.logger
          end

          def check_access_to_group!(group)
            token = Doorkeeper::OAuth::Token.from_request(
              current_request,
              *Doorkeeper.configuration.access_token_methods
            )
            unauthorized! unless token && GroupScimAuthAccessToken.token_matches_for_group?(token, group)
          end

          # Instance variable `@group` is necessary for the
          # Gitlab::ApplicationContext in API::API
          def find_and_authenticate_group!(group_path)
            @group = find_group(group_path)

            scim_not_found!(message: "Group #{group_path} not found") unless @group

            unless @group.saml_provider
              scim_not_found!(message: "Group #{group_path} does not have SAML SSO configured")
            end

            check_access_to_group!(@group)

            set_current_organization_from_group(@group)

            @group
          end

          # rubocop:disable Gitlab/AvoidCurrentOrganization -- Group SCIM does not go
          # through standard set_current_organization
          def set_current_organization_from_group(group)
            return if ::Current.organization_assigned

            ::Current.organization =
              ::Organizations::Organization.find_by_id_with_isolation_record(group.organization_id)

            check_organization_maintenance_mode!
          end
          # rubocop:enable Gitlab/AvoidCurrentOrganization

          def find_user_identity(group, extern_uid)
            return unless group.saml_provider

            group.scim_identities.with_extern_uid(extern_uid).first
          end

          # delete_deprovision handles the response and returns either
          # no_content! or a detailed error message.
          def delete_deprovision(identity)
            service = ::Gitlab::Scim::Group::DeprovisioningService.new(identity).execute

            if service.success?
              no_content!
            else
              logger.error(
                identity: identity,
                error: service.class.name,
                message: service.message,
                source: "#{__FILE__}:#{__LINE__}"
              )
              scim_error!(message: service.message)
            end
          end

          def patch_deprovision(identity)
            service = ::Gitlab::Scim::Group::DeprovisioningService.new(identity).execute

            if service.success?
              :success
            else
              logger.error(
                identity: identity,
                error: service.class.name,
                message: service.message,
                source: "#{__FILE__}:#{__LINE__}"
              )
              :error
            end
          end

          def reprovision(identity)
            return :conflict if ::Members::DeletionSchedule.exists_for?(identity.group, identity.user)
            return :success if identity.active?

            ::Gitlab::Scim::Group::ReprovisioningService.new(identity).execute

            :success
          rescue StandardError => e
            logger.error(identity: identity, error: e.class.name, message: e.message, source: "#{__FILE__}:#{__LINE__}")

            :error
          end

          def update_extern_uid(identity, extern_uid)
            identity.update(extern_uid: extern_uid) ? :success : :error
          end

          def scim_discovery_group
            find_and_authenticate_group!(params[:group])
          end
          strong_memoize_attr :scim_discovery_group

          def authenticate_scim_discovery!
            check_group_saml_configured

            return if Feature.enabled?(:scim_discovery_endpoints, scim_discovery_group)

            scim_not_found!(message: 'Not found')
          end

          def scim_discovery_base_url
            expose_url("/api/scim/v2/groups/#{scim_discovery_group.full_path}")
          end
        end

        mount_scim_discovery_endpoints(context: :group)

        resource :Users do
          before do
            check_group_saml_configured
          end

          desc 'Get SCIM users' do
            detail 'This feature was introduced in GitLab 11.10.'
            tags ['scim']
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          get do
            group = find_and_authenticate_group!(params[:group])
            results = ::Authn::GroupScimFinder.new(group).search(params)
            response_page = scim_paginate(results)

            status 200

            result_set = {
              resources: response_page,
              total_results: results.count,
              items_per_page: per_page(params[:count]),
              start_index: params[:startIndex]
            }
            present result_set, with: ::API::Entities::Scim::Users
          rescue ::Authn::GroupScimFinder::UnsupportedFilter, ScimFinder::UnsupportedFilter
            scim_error!(message: 'Unsupported Filter')
          end

          desc 'Get a SCIM user' do
            detail 'This feature was introduced in GitLab 11.10.'
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM ID of the user'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          get ':id', requirements: USER_ID_REQUIREMENTS do
            group = find_and_authenticate_group!(params[:group])

            identity = find_user_identity(group, params[:id])

            scim_not_found!(message: "Resource #{params[:id]} not found") unless identity

            status 200

            present identity, with: ::API::Entities::Scim::User
          end

          desc 'Create a SCIM user' do
            detail 'This feature was introduced in GitLab 11.10.'
            tags ['scim']
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          post do
            group = find_and_authenticate_group!(params[:group])
            parser = ::Gitlab::Scim::ParamsParser.new(params)
            result = ::Gitlab::Scim::Group::ProvisioningService.new(parser.post_params, group).execute

            case result.status
            when :success
              status 201

              present result.identity, with: ::API::Entities::Scim::User
            when :conflict
              scim_conflict!(
                message: "Error saving user with #{sanitize_request_parameters(params).inspect}: #{result.message}"
              )
            when :error
              scim_error!(
                message: [
                  "Error saving user with #{sanitize_request_parameters(params).inspect}",
                  result.message
                ].compact.join(": ")
              )
            end
          end

          desc 'Updates a SCIM user' do
            detail 'This feature was introduced in GitLab 11.10.'
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM ID of the user'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          patch ':id', requirements: USER_ID_REQUIREMENTS do
            scim_error!(message: 'Missing ID') unless params[:id]

            group = find_and_authenticate_group!(params[:group])
            identity = find_user_identity(group, params[:id])

            scim_not_found!(message: "Resource #{params[:id]} not found") unless identity

            result = update_scim_user(identity)

            case result
            when :success
              no_content!
            when :conflict
              scim_conflict!(
                message:
                _('User is pending deprovisioning. Please wait for the user to be deprovisioned and try again later.')
              )
            else
              scim_error!(
                message: "Error updating #{identity.user.name} with #{sanitize_request_parameters(params).inspect}"
              )
            end
          end

          desc 'Removes a SCIM user' do
            detail 'This feature was introduced in GitLab 11.10.'
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM ID of the user'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          delete ':id', requirements: USER_ID_REQUIREMENTS do
            scim_error!(message: 'Missing ID') unless params[:id]

            group = find_and_authenticate_group!(params[:group])
            identity = find_user_identity(group, params[:id])

            scim_not_found!(message: "Resource #{params[:id]} not found") unless identity

            delete_deprovision(identity)
          end
        end
      end
    end
  end
end
