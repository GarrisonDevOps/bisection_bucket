# frozen_string_literal: true

module Mutations
  module Geo
    module Registries
      class BulkUpdate < BaseMutation
        graphql_name 'GeoRegistriesBulkUpdate'
        description 'Mutates multiple Geo registries for a given registry class.'

        extend ::Gitlab::Utils::Override

        authorize :read_geo_registry
        authorize_granular_token permissions: :update_geo_registry, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :registry_class,
          ::Types::Geo::RegistryClassEnum,
          required: true,
          description: 'Class of the Geo registries to be updated.'

        argument :action,
          ::Types::Geo::RegistriesBulkActionEnum,
          required: true,
          description: 'Action to be executed on Geo registries.'

        argument :ids,
          [Types::GlobalIDType[::Geo::BaseRegistry]],
          required: false,
          description: 'Execute the action on registries selected by their ID.'

        argument :replication_state, ::Types::Geo::ReplicationStateEnum,
          required: false,
          description: 'Execute the action on registries selected by their replication state.'

        argument :verification_state, ::Types::Geo::VerificationStateEnum,
          required: false,
          description: 'Execute the action on registries selected by their verification state.'

        field :registry_class, ::Types::Geo::RegistryClassEnum, null: true, description: 'Updated Geo registry class.'

        def resolve(**args)
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_all_geo, :global)

          if args[:registry_class] == ::Geo::UploadRegistry.name && !::Geo::UploadReplicator.replication_enabled?
            return { registry_class: nil, errors: [upload_registry_error] }
          end

          result = ::Geo::RegistryBulkUpdateService
            .new(args[:action], args[:registry_class], registry_update_params(args))
            .execute

          { registry_class: result.payload[:registry_class], errors: result.errors }
        end

        override :read_only?
        def read_only?
          false
        end

        private

        def upload_registry_error
          s_("Geo|Uploads replicate by type, so UPLOAD_REGISTRY can't be updated. " \
            "You must use the registry class for each upload type, such as PROJECT_UPLOAD_REGISTRY.")
        end

        def registry_update_params(args)
          {
            ids: args[:ids]&.map { |gid| ::GitlabSchema.parse_gid(gid, expected_type:).model_id },
            replication_state: args[:replication_state],
            verification_state: args[:verification_state] ? "verification_#{args[:verification_state]}" : nil
          }.compact
        end

        def expected_type
          Types::Geo::RegistrableType::GEO_REGISTRY_TYPES.keys
        end
      end
    end
  end
end
