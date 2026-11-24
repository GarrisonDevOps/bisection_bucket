# frozen_string_literal: true

module Mutations
  module Ai
    module DomainSettings
      class NamespaceUpdate < Base
        graphql_name 'AiDomainSettingsNamespaceUpdate'
        description 'Adds or removes domains from the allowed or denied list for flows running in a sandboxed ' \
          'environment.'
        authorize :update_ai_domain_settings
        authorize_granular_token permissions: :update_ai_domain_settings,
          boundary_argument: :namespace_id, boundary_type: :group

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: true,
          description: 'Global ID of the root namespace to update.'

        def resolve(namespace_id:, action:, domain_setting_type:, domains:)
          namespace = authorized_find!(id: namespace_id)

          validation_error = validate_domains(action, domains)
          return validation_error if validation_error

          domains = normalize_domains(domains)

          current_domains = namespace_domains(namespace, domain_setting_type)
          updated_domains = compute_updated_domains(current_domains, action, domains)

          set_namespace_domains(namespace, domain_setting_type, updated_domains)

          if namespace.ai_settings.save
            build_result(action, current_domains, namespace_domains(namespace, domain_setting_type))
          else
            error_result(namespace.ai_settings.errors.full_messages)
          end
        end

        private

        def namespace_domains(namespace, domain_setting_type)
          (allowing?(domain_setting_type) ? namespace.ai_allowed_domains : namespace.ai_denied_domains) || []
        end

        def set_namespace_domains(namespace, domain_setting_type, domains)
          if allowing?(domain_setting_type)
            namespace.ai_allowed_domains = domains
          else
            namespace.ai_denied_domains = domains
          end
        end
      end
    end
  end
end
