# frozen_string_literal: true

module API
  module Scim
    class InstanceScim < ::API::Base
      extend ::API::Scim::DiscoveryEndpoints

      # Instance SCIM assigns Current.organization itself in
      # check_instance_requirements!. Disable the global fallback in
      # API::API's before_validation hook so it does not pre-empt that
      # assignment (which would trip OrganizationAlreadyAssignedError).
      skip_global_organization_setup!

      feature_category :user_management

      prefix 'api/scim'
      version 'v2'
      content_type :json, 'application/scim+json'
      USER_ID_REQUIREMENTS = { id: /.+/ }.freeze

      helpers ::EE::API::Helpers::ScimPagination
      helpers ::API::Helpers::ScimHelpers

      helpers do
        def scim_token
          @scim_token ||= ScimOauthAccessToken.find_by_token(
            Doorkeeper::OAuth::Token.from_request(
              current_request,
              *Doorkeeper.configuration.access_token_methods
            )
          )
        end

        def check_access!
          unauthorized! unless scim_token
        end

        def check_instance_requirements!
          not_found! if Gitlab.com?

          ::Current.organization = scim_token.organization
          check_instance_saml_configured
          not_found! unless ::License.feature_available?(:instance_level_scim)
        end

        def find_user_identity(extern_uid)
          ScimIdentity.for_instance.with_extern_uid(extern_uid).first
        end

        def patch_deprovision(identity)
          ::Gitlab::Scim::DeprovisioningService.new(identity).execute

          true
        rescue StandardError => e
          logger.error(
            identity: identity,
            error: e.class.name,
            message: e.message,
            source: "#{__FILE__}:#{__LINE__}"
          )
          scim_error!(message: e.message)
        end

        def reprovision(identity)
          identity.active? || ::Gitlab::Scim::ReprovisioningService.new(identity).execute

          true
        rescue StandardError => e
          logger.error(
            identity: identity,
            error: e.class.name,
            message: e.message,
            source: "#{__FILE__}:#{__LINE__}"
          )
          scim_error!(message: e.message)
        end

        def update_extern_uid(identity, extern_uid)
          identity.update(extern_uid: extern_uid)
        end
      end

      namespace 'application' do
        before { check_access! }

        helpers do
          def authenticate_scim_discovery!
            check_instance_requirements!

            scim_not_found!(message: 'Not found') unless Feature.enabled?(:scim_discovery_endpoints, :instance)
          end

          def scim_discovery_base_url
            expose_url('/api/scim/v2/application')
          end
        end

        mount_scim_discovery_endpoints(context: :instance)

        resource :Users do
          helpers do
            def scim_groups_by_user_id(user_ids)
              return {} if user_ids.blank?

              memberships = ::Authn::ScimGroupMembership.by_user_id(user_ids)
              scim_group_uids = memberships.map(&:scim_group_uid).uniq
              display_names = scim_group_display_names(scim_group_uids)

              memberships.group_by(&:user_id).transform_values do |rows|
                rows.filter_map do |row|
                  name = display_names[row.scim_group_uid]

                  { scim_group_uid: row.scim_group_uid, name: name } if name
                end
              end
            end

            def scim_group_display_names(scim_group_uids)
              return {} if scim_group_uids.empty?

              ::SamlGroupLink.by_scim_group_uid(scim_group_uids)
                .each_with_object({}) do |link, names|
                  names[link.scim_group_uid] ||= link.saml_group_name
                end
            end
          end

          before { check_instance_requirements! }

          desc 'List all SCIM users' do
            detail 'Lists all SCIM users.'
            success ::API::Entities::Scim::Users
            tags ['scim']
          end

          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          get do
            results = ScimFinder.new.search(params)
            response_page = scim_paginate(results)

            status :ok
            result_set = {
              resources: response_page,
              total_results: results.count,
              items_per_page: per_page(params[:count]),
              start_index: params[:startIndex]
            }

            scim_groups = scim_groups_by_user_id(response_page.map(&:user_id))

            present result_set, with: ::API::Entities::Scim::Users, scim_groups: scim_groups
          rescue ScimFinder::UnsupportedFilter
            scim_error!(message: 'Unsupported Filter')
          end

          desc 'Retrieve a SCIM user' do
            detail 'Retrieves a SCIM user by their SCIM ID.'
            success ::API::Entities::Scim::Users
            tags ['scim']
          end

          params do
            requires :id, type: String, desc: 'The SCIM ID of the user'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          get ':id', requirements: USER_ID_REQUIREMENTS do
            identity = ScimIdentity.with_extern_uid(params[:id]).first
            scim_not_found!(message: "Resource #{params[:id]} not found") unless identity

            status 200

            present identity, with: ::API::Entities::Scim::User,
              scim_groups: scim_groups_by_user_id([identity.user_id])
          end

          desc 'Create a SCIM user' do
            detail 'Creates and provisions a SCIM user.'
            success ::API::Entities::Scim::Users
            tags ['scim']
          end

          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          post do
            parser = ::Gitlab::Scim::ParamsParser.new(params)
            result = ::Gitlab::Scim::ProvisioningService.new(
              parser.post_params.merge(organization_id: ::Current.organization.id)
            ).execute

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

          desc 'Update a SCIM user' do
            detail 'Updates a SCIM user.'
            success code: 204
            tags ['scim']
          end

          params do
            requires :id, type: String, desc: 'The SCIM ID of the user'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          patch ':id', requirements: USER_ID_REQUIREMENTS do
            identity = find_user_identity(params[:id])
            scim_not_found!(message: "Resource #{params[:id]} not found") unless identity
            updated = update_scim_user(identity)

            if updated
              no_content!
            else
              scim_error!(
                message: "Error updating #{identity.user.name} with #{sanitize_request_parameters(params).inspect}"
              )
            end
          end

          desc 'Delete a SCIM user' do
            detail 'Deletes and deprovisions a SCIM user.'
            success code: 204
            tags ['scim']
          end

          params do
            requires :id, type: String, desc: 'The SCIM ID of the user'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          delete ':id', requirements: USER_ID_REQUIREMENTS do
            identity = find_user_identity(params[:id])
            scim_not_found!(message: "Resource #{params[:id]} not found") unless identity
            patch_deprovision(identity)
            no_content!
          end
        end

        resource :Groups do
          helpers do
            def find_group_link(scim_group_uid)
              # We only need one group link since they'll all have the same name and SCIM ID.
              # Multiple links can exist if the same SAML group is linked to different GitLab groups.
              group_link = SamlGroupLink.first_by_scim_group_uid(scim_group_uid)

              scim_not_found!(message: "Group #{scim_group_uid} not found") unless group_link
              group_link
            end

            def scim_members_for(scim_group_uids)
              ::Authn::ScimGroupMembership.members_by_scim_group_uid(scim_group_uids)
                .group_by(&:scim_group_uid)
                .transform_values do |rows|
                  rows.map { |row| { extern_uid: row.member_extern_uid, name: row.member_name } }
                end
            end
          end

          before do
            check_instance_requirements!
          end

          desc 'Create a SCIM group' do
            detail 'Associates SCIM group ID with existing SAML group link'
            success ::API::Entities::Scim::Group
            tags ['scim']
          end
          params do
            requires :displayName, type: String, desc: 'Name of the group as configured in GitLab'
            optional :externalId, type: String, desc: 'SCIM group ID'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          post do
            result = ::Gitlab::Scim::GroupSyncProvisioningService.new(
              saml_group_name: params[:displayName],
              scim_group_uid: params[:externalId] || SecureRandom.uuid
            ).execute

            case result.status
            when :success
              status 201
              # A newly associated group has no members yet; members are only added by
              # subsequent PATCH/PUT operations, so skip the lookup and return an empty set.
              present result.group_link, with: ::API::Entities::Scim::Group, scim_members: {}
            when :error
              scim_error!(message: result.message)
            end
          end

          desc 'Get a SCIM group' do
            detail 'Retrieves a SCIM group by its ID'
            success ::API::Entities::Scim::Group
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM group ID'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          get ':id' do
            group_link = find_group_link(params[:id])
            present group_link, with: ::API::Entities::Scim::Group,
              scim_members: scim_members_for([group_link.scim_group_uid])
          end

          desc 'List all SCIM groups' do
            detail 'Lists all SCIM groups.'
            success ::API::Entities::Scim::Groups
            tags ['scim']
          end
          params do
            optional :filter, type: String, desc: 'Filter string (e.g. displayName eq "Engineering")'
            optional :count, type: Integer, desc: 'Number of results per page'
            optional :startIndex, type: Integer, desc: 'Page offset'
            optional :excludedAttributes, type: String, desc: 'Comma-separated list of attributes to exclude'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          get do
            results = ::Authn::ScimGroupFinder.new.search(params)
            response_page = scim_paginate(results)

            excluded_attributes = (params[:excludedAttributes] || '').split(',').map(&:strip)

            scim_members =
              if excluded_attributes.include?('members')
                {}
              else
                scim_members_for(response_page.map(&:scim_group_uid))
              end

            result_set = {
              resources: response_page,
              total_results: results.count,
              items_per_page: per_page(params[:count]),
              start_index: params[:startIndex]
            }

            status :ok
            present result_set, with: ::API::Entities::Scim::Groups,
              excluded_attributes: excluded_attributes, scim_members: scim_members
          rescue ::Authn::ScimGroupFinder::UnsupportedFilter
            scim_error!(message: 'Unsupported Filter')
          end

          desc 'Update a SCIM group' do
            detail 'Updates a SCIM group.'
            success code: 204
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM group ID'
            requires :schemas, type: Array, desc: 'SCIM schemas'
            requires :Operations, type: Array, allow_blank: false, desc: 'Operations to perform' do
              requires :op, type: String,
                coerce_with: ->(v) { v.to_s.downcase },
                values: %w[add remove replace],
                desc: 'Operation type'
              optional :path, type: String, desc: 'Path to modify'
              optional :value, types: [Array, String, Hash], desc: 'Value for the operation'
            end
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          patch ':id' do
            saml_group_links = SamlGroupLink.by_scim_group_uid(params[:id])
            scim_not_found!(message: "Group #{params[:id]} not found") unless saml_group_links.exists?

            result = ::Gitlab::Scim::GroupSyncPatchService.new(
              scim_group_uid: params[:id],
              operations: params[:Operations]
            ).execute

            scim_bad_request!(message: result.message, scim_type: result.payload[:scim_type]) if result.error?

            no_content!
          end

          desc 'Replace a SCIM group' do
            detail 'Replaces a SCIM group.'
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM group ID'
            requires :schemas, type: Array, desc: 'SCIM schemas'
            requires :displayName, type: String, desc: 'Group display name'
            optional :externalId, type: String, desc: 'SCIM group ID'
            optional :members, type: Array, desc: 'Group members'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          put ':id' do
            saml_group_links = SamlGroupLink.by_scim_group_uid(params[:id])
            scim_not_found!(message: "Group #{params[:id]} not found") unless saml_group_links.exists?

            result = ::Gitlab::Scim::GroupSyncPutService.new(
              scim_group_uid: params[:id],
              members: params[:members] || [],
              display_name: params[:displayName],
              external_id: params[:externalId]
            ).execute

            scim_bad_request!(message: result.message, scim_type: result.payload[:scim_type]) if result.error?

            present saml_group_links.first, with: ::API::Entities::Scim::Group, excluded_attributes: ['members']
          end

          desc 'Delete a SCIM group' do
            detail 'Deletes a SCIM group.'
            tags ['scim']
          end
          params do
            requires :id, type: String, desc: 'The SCIM group ID'
          end
          route_setting :authorization, skip_granular_token_authorization: :scim_token_auth
          delete ':id' do
            saml_group_links = SamlGroupLink.by_scim_group_uid(params[:id])
            scim_not_found!(message: "Group #{params[:id]} not found") unless saml_group_links.exists?

            result = ::Gitlab::Scim::GroupSyncDeletionService.new(scim_group_uid: params[:id]).execute
            scim_error!(message: result.message) if result.error?

            no_content!
          end
        end
      end
    end
  end
end
