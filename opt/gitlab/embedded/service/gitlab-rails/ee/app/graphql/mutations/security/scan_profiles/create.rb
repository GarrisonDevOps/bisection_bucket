# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      class Create < BaseMutation
        graphql_name 'SecurityScanProfileCreate'

        include TriggerArguments

        authorize :create_security_scan_profiles
        authorize_granular_token permissions: :create_security_scan_profiles, boundary_argument: :namespace_id,
          boundary_type: :group

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: true,
          description: 'Global ID of the top level namespace to create the scan profile for.'

        argument :scan_type, ::Types::Security::ScanProfileTypeEnum,
          required: true,
          description: 'Type of the scan profile.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the scan profile.'

        argument :description, GraphQL::Types::String,
          required: true,
          description: 'Description of the scan profile.'

        argument :triggers, [::Types::Security::ScanProfiles::TriggerInputType],
          required: true, validates: { length: { minimum: 1 } },
          description: 'Triggers with optional configuration for the scan profile. At least one is required.'

        argument :strip_defaults, GraphQL::Types::Boolean,
          required: false,
          default_value: true,
          description: 'When true, trigger configuration values equal to the defaults are removed before storage ' \
            'so only overrides are persisted. When false, the configuration is stored as provided, ignoring defaults.'

        field :scan_profile, ::Types::Security::ScanProfileType,
          null: true,
          description: 'Created scan profile.'

        def resolve(namespace_id:, scan_type:, name:, triggers:, strip_defaults:, description: nil)
          namespace = authorized_find!(id: namespace_id)
          validate_namespace!(namespace)
          validate_scan_type!(namespace, scan_type)

          params = {
            scan_type: scan_type,
            name: name,
            description: description,
            strip_defaults: strip_defaults,
            triggers: build_triggers(triggers, scan_type)
          }

          result = ::Security::ScanProfiles::CreateScanProfileService.new(namespace, params, current_user).execute

          if result.success?
            { scan_profile: result.payload[:scan_profile], errors: [] }
          else
            { scan_profile: nil, errors: [result.message] }
          end
        end

        private

        def validate_namespace!(namespace)
          return if namespace.root?

          raise ::Gitlab::Graphql::Errors::ArgumentError, 'namespace_id must reference a top-level namespace.'
        end

        def validate_scan_type!(namespace, scan_type)
          if scan_type == 'business_logic' &&
              !::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(namespace)
            raise_resource_not_available_error!
          end

          raise_resource_not_available_error! if scan_type == 'skillguard' &&
            Feature.disabled?(:skillguard_analyzer, namespace)

          return unless scan_type == 'triage_and_remediation'

          raise_resource_not_available_error! unless Feature.enabled?(:triage_and_remediation_profile, namespace)
        end
      end
    end
  end
end
