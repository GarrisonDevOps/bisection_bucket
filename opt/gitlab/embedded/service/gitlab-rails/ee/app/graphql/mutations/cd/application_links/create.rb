# frozen_string_literal: true

module Mutations
  module Cd
    module ApplicationLinks
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdApplicationLinkCreate'
        description 'Creates a link on a continuous deployment application.'

        authorize :create_cd_application_link
        authorize_granular_token permissions: :create_cd_application_link,
          boundary: :instance,
          boundary_type: :instance

        argument :application_id, ::Types::GlobalIDType[::Cd::Application],
          required: true,
          description: 'Global ID of the application to create the link in.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::ApplicationLinkType, :name)

        argument :url, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::ApplicationLinkType, :url)

        argument :link_type, ::Types::Cd::ApplicationLinkTypeEnum,
          required: true,
          description: copy_field_description(::Types::Cd::ApplicationLinkType, :link_type)

        field :application_link, ::Types::Cd::ApplicationLinkType,
          null: true,
          description: 'Link created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application = authorized_find!(application_id: args.delete(:application_id))

          response = ::Cd::ApplicationLinks::CreateService
            .new(parent: application, current_user: current_user, params: args)
            .execute

          {
            application_link: response.success? ? response.payload[:application_link] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(application_id:)
          ::GitlabSchema.object_from_id(application_id, expected_type: ::Cd::Application).sync
        end
      end
    end
  end
end
