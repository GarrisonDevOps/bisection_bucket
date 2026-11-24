# frozen_string_literal: true

module Gitlab
  module CustomRoles
    class Definition
      include ::Gitlab::CustomRoles::Shared

      WIP_ENV_VAR = 'GITLAB_LOAD_WIP_CUSTOM_ABILITIES'

      class << self
        attr_accessor :definitions

        # Returns all loaded permission definitions. Permissions whose YAML
        # carries `wip: true` are excluded unless the
        # GITLAB_LOAD_WIP_CUSTOM_ABILITIES env var is set, in which case wip
        # permissions are loaded for local development.
        def all
          @all_definitions ||= sort(standard.merge(admin))
        end

        def admin
          @admin_definitions ||= load_definitions(admin_path)
        end

        def standard
          @standard_definitions ||= load_definitions(standard_path)
        end

        def load_abilities!
          @all_definitions = nil
          @standard_definitions = load_definitions(standard_path)
          @admin_definitions = load_definitions(admin_path)
        end

        private

        def filter_wip?(definition)
          return false if ::Gitlab::Utils.to_boolean(ENV[WIP_ENV_VAR], default: false)

          definition[:wip]
        end

        def standard_path
          Rails.root.join("ee/config/custom_abilities/*.yml")
        end

        def admin_path
          Rails.root.join("ee/config/custom_abilities/admin/*.yml")
        end

        def load_definitions(path)
          definitions = {}

          Dir.glob(path).each do |file|
            definition = load_from_file(file)
            next if filter_wip?(definition)

            name = definition[:name].to_sym
            definitions[name] = definition
          end

          sort(definitions)
        end

        def load_from_file(path)
          definition = File.read(path)
          definition = YAML.safe_load(definition)
          sanitize(definition)
        end

        def sort(definitions)
          definitions.sort_by { |_, value| value[:title].downcase }.to_h
        end

        def sanitize(definition)
          definition = definition.deep_symbolize_keys

          # Uses options_with_owner.values rather than options_for_custom_roles.values
          # because these arrays are used in the privilege escalation check - without
          # Owner included, owners would not be able to assign custom roles
          # with abilities included in their base access.
          valid_access_levels = Gitlab::Access.options_with_owner.values

          %i[enabled_for_group_access_levels enabled_for_project_access_levels].each do |key|
            next unless definition[key]

            definition[key] = definition[key] & valid_access_levels
          end

          definition
        end
      end
    end
  end
end
