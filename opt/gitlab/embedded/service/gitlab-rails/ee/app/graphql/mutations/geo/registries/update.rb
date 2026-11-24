# frozen_string_literal: true

module Mutations
  module Geo
    module Registries
      class Update < BaseMutation
        graphql_name 'GeoRegistriesUpdate'
        description 'Mutates a Geo registry.'

        extend ::Gitlab::Utils::Override

        authorize :read_geo_registry
        authorize_granular_token permissions: :update_geo_registry, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :registry_id,
          Types::GlobalIDType[::Geo::BaseRegistry],
          required: true,
          description: 'ID of the Geo registry entry to be updated.'

        argument :action,
          ::Types::Geo::RegistryActionEnum,
          required: true,
          description: 'Action to be executed on a Geo registry.'

        field :registry, ::Types::Geo::RegistrableType, null: true, description: 'Updated Geo registry entry.'

        def resolve(action:, registry_id:)
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_all_geo, :global)

          if registry_id.model_class == ::Geo::UploadRegistry && !::Geo::UploadReplicator.replication_enabled?
            return { registry: nil, errors: [upload_registry_error] }
          end

          registry = authorized_find!(id: registry_id)

          result = ::Geo::RegistryUpdateService.new(action, registry).execute

          { registry: result.payload[:registry], errors: result.errors }
        end

        override :read_only?
        def read_only?
          false
        end

        private

        def upload_registry_error
          s_("Geo|Uploads replicate by type, so upload registries can't be updated. " \
            "You must use the registry for each upload type, such as a ProjectUploadRegistry.")
        end
      end
    end
  end
end
