# frozen_string_literal: true

module Mutations
  module Cd
    module Applications
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdApplicationCreate'
        description 'Creates a continuous deployment application in an organization.'

        authorize :create_cd_application
        authorize_granular_token permissions: :create_cd_application,
          boundary: :instance,
          boundary_type: :instance

        argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
          required: true,
          description: 'Global ID of the organization to create the application in.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::ApplicationType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ApplicationType, :description)

        argument :services, [::Types::Cd::ServiceInputType],
          required: false,
          validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Services to create in the application, ' \
            "up to #{::Types::BaseArgument::MAX_ARRAY_SIZE}."

        field :application, ::Types::Cd::ApplicationType,
          null: true,
          description: 'Application created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          organization = authorized_find!(organization_id: args.delete(:organization_id))
          args[:services] = build_services(args[:services])

          response = ::Cd::Applications::CreateService
            .new(parent: organization, current_user: current_user, params: args)
            .execute

          {
            application: response.success? ? response.payload[:application] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(organization_id:)
          ::GitlabSchema.object_from_id(organization_id, expected_type: ::Organizations::Organization).sync
        end

        def build_services(services)
          Array(services).map do |service|
            {
              name: service[:name],
              description: service[:description],
              artifact_sources: build_artifact_sources(service[:artifact_sources])
            }
          end
        end

        def build_artifact_sources(artifact_sources)
          Array(artifact_sources).map do |artifact_source|
            attrs = { name: artifact_source[:name], source_ref: artifact_source[:source_ref] }
            # Only set source_config when given: an unset optional input argument reads back as
            # nil here, and merging that in would override the model's non-null jsonb default.
            attrs[:source_config] = artifact_source[:source_config] if artifact_source[:source_config].present?
            attrs
          end
        end
      end
    end
  end
end
