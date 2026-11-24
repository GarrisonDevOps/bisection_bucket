# frozen_string_literal: true

module API
  class ProviderIdentity < ::API::Base
    include ::Gitlab::Utils::StrongMemoize

    UID_REQUIREMENTS = { uid: ::API::NO_SLASH_URL_PART_REGEX }.merge(::API::NO_FORMAT_SUFFIX_REQUIREMENT).freeze

    before { authenticate! }
    before { authorize_admin_group }

    feature_category :system_access

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups do
      %w[saml scim].each do |provider_type|
        resource ":id/#{provider_type}", requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc "Retrieve #{provider_type.upcase} identities for a group" do
            detail "Retrieves #{provider_type.upcase} identities for a group."
            success ::API::Entities::IdentityDetail
            is_array true
            tags ['provider_identities']
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :"read_#{provider_type}_identity", boundary_type: :group
          get "/identities" do
            group = find_group(params[:id])

            case provider_type
            when 'saml'
              bad_request! unless group.saml_provider
              present group.saml_provider.identities, with: ::API::Entities::IdentityDetail
            when 'scim'
              present group.scim_identities, with: ::API::Entities::IdentityDetail
            end
          end

          desc "Retrieve a #{provider_type.upcase} identity" do
            detail "Retrieves a specified #{provider_type.upcase} identity."
            success ::API::Entities::IdentityDetail
            tags ['provider_identities']
          end
          params do
            requires :uid, type: String, desc: 'External UID of the user.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :"read_#{provider_type}_identity", boundary_type: :group
          get ':uid', requirements: UID_REQUIREMENTS do
            group = find_group(params[:id])
            identity = find_provider_identity(provider_type, params[:uid], group)

            not_found!('Identity') unless identity

            present identity, with: ::API::Entities::IdentityDetail
          end

          desc "Update `extern_uid` field for a #{provider_type.upcase} identity" do
            detail "Updates the `extern_uid` field for a specified #{provider_type.upcase} identity."
            success ::API::Entities::IdentityDetail
            tags ['provider_identities']
          end

          params do
            requires :uid, type: String, desc: 'External UID of the user.'
            requires :extern_uid, type: String, desc: 'New external UID of the user.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :"update_#{provider_type}_identity", boundary_type: :group
          patch ':uid', requirements: UID_REQUIREMENTS do
            group = find_group(params[:id])
            identity = find_provider_identity(provider_type, params[:uid], group)

            not_found!('Identity') unless identity

            if identity.update(extern_uid: params[:extern_uid])
              present identity, with: ::API::Entities::IdentityDetail
            else
              render_api_error!(identity.errors.full_messages.join(",").to_s, 400)
            end
          end

          desc "Delete a #{provider_type.upcase} identity" do
            detail "Deletes a specified #{provider_type.upcase} identity."
            success ::API::Entities::IdentityDetail
            tags ['provider_identities']
          end

          params do
            requires :uid, type: String, desc: 'External UID of the user.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :"delete_#{provider_type}_identity", boundary_type: :group
          delete ':uid', requirements: UID_REQUIREMENTS do
            group = find_group(params[:id])
            identity = find_provider_identity(provider_type, params[:uid], group)

            not_found!('Identity') unless identity

            identity.delete
            no_content!
          end
        end
      end
    end

    helpers do
      def find_provider_identity(provider_type, extern_uid, group)
        case provider_type
        when 'scim'
          group.scim_identities.with_extern_uid(extern_uid).first
        when 'saml'
          GroupSamlIdentityFinder.find_by_group_and_uid(group: group, uid: extern_uid)
        end
      end
    end
  end
end
