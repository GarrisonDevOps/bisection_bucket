# frozen_string_literal: true

module Mutations
  module Cd
    module ApplicationLinks
      class Update < ::Mutations::BaseMutation
        graphql_name 'CdApplicationLinkUpdate'
        description 'Updates a link on a continuous deployment application.'

        authorize :update_cd_application_link
        authorize_granular_token permissions: :update_cd_application_link,
          boundary: :instance,
          boundary_type: :instance

        argument :id, ::Types::GlobalIDType[::Cd::ApplicationLink],
          required: true,
          description: 'Global ID of the link to update.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ApplicationLinkType, :name)

        argument :url, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ApplicationLinkType, :url)

        argument :link_type, ::Types::Cd::ApplicationLinkTypeEnum,
          required: false,
          description: copy_field_description(::Types::Cd::ApplicationLinkType, :link_type)

        field :application_link, ::Types::Cd::ApplicationLinkType,
          null: true,
          description: 'Link updated by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application_link = authorized_find!(id: args.delete(:id))

          response = ::Cd::ApplicationLinks::UpdateService
            .new(application_link, current_user: current_user, params: args)
            .execute

          updated_link = response.payload[:application_link]

          {
            application_link: response.success? ? updated_link : nil,
            errors: response.errors
          }
        end

        private

        def find_object(id:)
          ::GitlabSchema.object_from_id(id, expected_type: ::Cd::ApplicationLink).sync
        end
      end
    end
  end
end
