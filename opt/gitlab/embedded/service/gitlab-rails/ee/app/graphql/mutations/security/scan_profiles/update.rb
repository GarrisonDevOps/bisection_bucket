# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      class Update < BaseMutation
        graphql_name 'SecurityScanProfileUpdate'

        include TriggerArguments

        authorize :update_security_scan_profiles
        authorize_granular_token permissions: :update_security_scan_profiles, boundary_argument: :id,
          boundary: :namespace, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::Security::ScanProfile],
          required: true,
          description: 'Global ID of the scan profile to update.'

        argument :name, GraphQL::Types::String,
          required: false,
          validates: { allow_null: false },
          description: 'Name of the scan profile.'

        argument :description, GraphQL::Types::String,
          required: false,
          validates: { allow_null: false },
          description: 'Description of the scan profile.'

        argument :triggers, [::Types::Security::ScanProfiles::TriggerInputType],
          required: false, validates: { length: { minimum: 1 }, allow_null: true },
          description: 'Complete set of triggers with optional configuration for the scan profile. ' \
            'When provided, triggers omitted from the list are removed, ' \
            'and a trigger sent without a configuration has its existing configuration removed.'

        argument :strip_defaults, GraphQL::Types::Boolean,
          required: false,
          default_value: true,
          description: 'When true, trigger configuration values equal to the defaults are removed before storage ' \
            'so only overrides are persisted. When false, the configuration is stored as provided, ignoring defaults.'

        field :scan_profile, ::Types::Security::ScanProfileType,
          null: true,
          description: 'Updated scan profile.'

        def resolve(id:, strip_defaults:, **args)
          profile = authorized_find!(id: id)
          raise_resource_not_available_error! if profile.deleted?

          return not_editable_error(profile) if profile.gitlab_recommended?

          validate_scan_type!(profile)

          params = build_params(profile, strip_defaults, args)
          result = ::Security::ScanProfiles::UpdateService.new(profile, params, current_user).execute

          if result.success?
            { scan_profile: result.payload[:scan_profile], errors: [] }
          else
            { scan_profile: profile.reset, errors: [result.message] }
          end
        end

        private

        def validate_scan_type!(profile)
          if profile.scan_type == 'business_logic' &&
              !::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(profile.namespace)
            raise_resource_not_available_error!
          end

          raise_resource_not_available_error! if profile.scan_type == 'skillguard' &&
            Feature.disabled?(:skillguard_analyzer, profile.namespace)

          return unless profile.scan_type == 'triage_and_remediation'

          raise_resource_not_available_error! unless
            Feature.enabled?(:triage_and_remediation_profile, profile.namespace)
        end

        def not_editable_error(profile)
          # GitLab-recommended profiles are system-managed and are non-editable
          {
            scan_profile: profile,
            errors: [s_('SecurityScanProfile|Default GitLab-recommended profiles are not editable.')]
          }
        end

        def find_object(id:)
          GitlabSchema.object_from_id(id)
        end

        def build_params(profile, strip_defaults, args)
          params = args.slice(:name, :description)
          params[:strip_defaults] = strip_defaults
          params[:triggers] = build_triggers(args[:triggers], profile.scan_type) if args[:triggers]
          params
        end
      end
    end
  end
end
