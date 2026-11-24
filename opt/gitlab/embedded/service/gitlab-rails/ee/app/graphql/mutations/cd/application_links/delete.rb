# frozen_string_literal: true

module Mutations
  module Cd
    module ApplicationLinks
      class Delete < ::Mutations::BaseMutation
        graphql_name 'CdApplicationLinkDelete'
        description 'Deletes a link on a continuous deployment application.'

        authorize :delete_cd_application_link
        authorize_granular_token permissions: :delete_cd_application_link,
          boundary: :instance,
          boundary_type: :instance

        argument :id, ::Types::GlobalIDType[::Cd::ApplicationLink],
          required: true,
          description: 'Global ID of the link to delete.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application_link = authorized_find!(id: args[:id])

          response = ::Cd::ApplicationLinks::DeleteService
            .new(application_link, current_user: current_user)
            .execute

          { errors: response.errors }
        end

        private

        def find_object(id:)
          ::GitlabSchema.object_from_id(id, expected_type: ::Cd::ApplicationLink).sync
        end
      end
    end
  end
end
