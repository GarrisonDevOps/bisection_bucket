# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class RestrictionsEnforcer
      include RemoteDevelopmentConstants
      include Messages

      MAX_VOLUME_NAME_LIMIT = 28

      MAX_DEVFILE_SIZE_BYTES = 3.megabytes

      # Since this is called after flattening the devfile, we can safely assume that it has valid syntax
      # as per devfile standard. If you are validating something that is not available across all devfile versions,
      # add additional guard clauses.

      # Currently, we only support 'container' and 'volume' type components.
      UNSUPPORTED_COMPONENT_TYPES = %i[kubernetes openshift image].freeze

      # Currently, we only support 'exec' and 'apply' for validation
      SUPPORTED_COMMAND_TYPES = %i[exec apply].freeze

      # Currently, we only support `preStart` events
      SUPPORTED_EVENTS = %i[preStart postStart].freeze

      # Currently, we only support the following options for exec commands
      SUPPORTED_EXEC_COMMAND_OPTIONS = %i[commandLine component label hotReloadCapable workingDir].freeze

      # Currently, we only support the default value `false` for the `hotReloadCapable` option
      SUPPORTED_HOT_RELOAD_VALUE = false

      # Override command must be a boolean value
      SUPPORTED_OVERRIDE_COMMAND_VALUE = [true, false].freeze

      # @param [Hash] parent_context
      # @return [Gitlab::Fp::Result]
      def self.enforce(parent_context)
        context = {
          # NOTE: `processed_devfile` is not available in the context until the devfile has been flattened.
          #       If the devfile is flattened, use `processed_devfile`. Else, use `devfile`.
          devfile: parent_context[:processed_devfile] || parent_context[:devfile],
          is_processed_devfile: parent_context[:processed_devfile].present?,
          errors: []
        }

        initial_result = Gitlab::Fp::Result.ok(context)

        result =
          initial_result
            .and_then(method(:validate_devfile_size))
            .map(method(:validate_schema_version))
            .map(method(:validate_parent))
            .map(method(:validate_projects))
            .map(method(:validate_root_attributes))
            .map(method(:validate_components))
            .map(method(:validate_containers))
            .map(method(:validate_endpoints))
            .map(method(:validate_commands))
            .map(method(:validate_events))
            .map(method(:validate_variables))

        case result
        in { ok: { errors: [] } }
          Gitlab::Fp::Result.ok(parent_context)
        in { ok: { errors: errors } }
          Gitlab::Fp::Result.err(DevfileRestrictionsFailed.new({ details: errors, context: parent_context }))
        in { err: DevfileSizeLimitExceeded => message }
          Gitlab::Fp::Result.err(
            DevfileRestrictionsFailed.new({ details: message.content[:details], context: parent_context })
          )
        else
          raise Gitlab::Fp::UnmatchedResultError.new(result: result)
        end
      end

      # @param [Hash] context
      # @return [Gitlab::Fp::Result]
      def self.validate_devfile_size(context)
        context => { devfile: Hash => devfile }

        # Calculate the size of the devfile by converting it to JSON
        devfile_json = devfile.to_json
        devfile_size_bytes = devfile_json.bytesize

        if devfile_size_bytes > MAX_DEVFILE_SIZE_BYTES
          details = format(_("Devfile size (%{current_size}) exceeds the maximum allowed size of %{max_size}"),
            current_size: ActiveSupport::NumberHelper.number_to_human_size(devfile_size_bytes),
            max_size: ActiveSupport::NumberHelper.number_to_human_size(MAX_DEVFILE_SIZE_BYTES)
          )
          return Gitlab::Fp::Result.err(
            DevfileSizeLimitExceeded.new(
              { details: details, context: context }
            )
          )
        end

        Gitlab::Fp::Result.ok(context)
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_schema_version(context)
        devfile = context[:devfile]

        devfile_schema_version_string = devfile.fetch(:schemaVersion, "")

        unless devfile_schema_version_string.is_a?(String)
          return append_err(_("'schemaVersion' must be a String"), context)
        end

        begin
          devfile_schema_version = Gem::Version.new(devfile_schema_version_string)
        rescue ArgumentError
          append_err(
            format(_("Invalid 'schemaVersion' '%{schema_version}'"), schema_version: devfile_schema_version_string),
            context
          )
        end

        minimum_schema_version = Gem::Version.new(REQUIRED_DEVFILE_SCHEMA_VERSION)
        unless devfile_schema_version == minimum_schema_version
          append_err(
            format(_("'schemaVersion' '%{given_version}' is not supported, it must be '%{required_version}'"),
              given_version: devfile_schema_version_string,
              required_version: REQUIRED_DEVFILE_SCHEMA_VERSION
            ),
            context
          )
        end

        context
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_parent(context)
        devfile = context[:devfile]
        append_err(_("Inheriting from 'parent' is not yet supported"), context) if devfile.has_key?(:parent)

        context
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_projects(context)
        devfile = context[:devfile]
        append_err(_("'starterProjects' is not yet supported"), context) if devfile.has_key?(:starterProjects)
        append_err(_("'projects' is not yet supported"), context) if devfile.has_key?(:projects)

        context
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_root_attributes(context)
        devfile = context[:devfile]
        root_attributes = devfile.fetch(:attributes, {})

        return append_err(_("'Attributes' must be a Hash"), context) unless root_attributes.is_a?(Hash)

        if devfile.dig(:attributes, :"pod-overrides")
          append_err(_("Attribute 'pod-overrides' is not yet supported"), context)
        end

        context
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_components(context)
        devfile = context[:devfile]

        components = devfile.fetch(:components, [])
        return append_err(_("'Components' must be an Array"), context) unless components.is_a?(Array)
        return append_err(_("No components present in devfile"), context) if components.blank?

        append_err(_("Each element in 'components' must be a Hash"), context) unless components.all?(Hash)

        injected_main_components = []

        components.each do |component|
          validate_component(context, component)
          next unless component.is_a?(Hash)
          next unless component.fetch(:attributes, {}).is_a?(Hash)

          injected_main_components << component if component.dig(:attributes, MAIN_COMPONENT_INDICATOR_ATTRIBUTE.to_sym)
        end

        if injected_main_components.empty?
          append_err(
            format(_("No component has '%{attribute}' attribute"), attribute: MAIN_COMPONENT_INDICATOR_ATTRIBUTE),
            context
          )
        end

        if injected_main_components.length > 1
          append_err(
            format(
              _("Multiple components '%{name}' have '%{attribute}' attribute"),
              name: injected_main_components.pluck(:name), # rubocop:disable CodeReuse/ActiveRecord -- this pluck isn't from ActiveRecord, it's from ActiveSupport
              attribute: MAIN_COMPONENT_INDICATOR_ATTRIBUTE
            ),
            context
          )
        end

        context
      end

      # @param [Hash] context
      # @return [Hash]

      def self.validate_containers(context)
        devfile = context[:devfile]

        components = devfile.fetch(:components, [])

        # There is no need to append an error here since it has already been done before this code is executed.
        return context unless components.is_a?(Array)

        components.each do |component|
          # There is no need to append an error here since it has already been done before this code is executed.
          return context unless component.is_a?(Hash)

          container = component.fetch(:container, {})
          component_name = component.fetch(:name, "")

          # There is no need to append an error here since it has already been done before this code is executed.
          unless container.is_a?(Hash)
            return append_err(
              format(_("'container' in component '%{component}' must be a Hash"), component: component_name), context)
          end

          validate_container_properties(context, container, component)
        end

        context
      end

      # @param [Hash] context
      # @param [Hash] container
      # @param [Hash] component
      # @return [Hash]
      def self.validate_container_properties(context, container, component)
        is_processed_devfile = context[:is_processed_devfile]

        component_name = component.fetch(:name, "")

        if container[:dedicatedPod]
          append_err(format(_("Property 'dedicatedPod' of component '%{component}' is not yet supported"),
            component: component_name), context)
        end

        if container[:sourceMapping]
          append_err(format(_("Property 'sourceMapping' of component '%{component}' is not yet supported"),
            component: component_name), context)
        end

        if container[:mountSources] && !is_processed_devfile
          append_err(format(_("Property 'mountSources' of component '%{component}' is not yet supported"),
            component: component_name), context)
        end

        attributes = component.fetch(:attributes, {})
        unless attributes.is_a?(Hash)
          return append_err(
            format(_("'attributes' in component '%{component}' must be a Hash"), component: component_name), context)
        end

        override_command = attributes.fetch(:overrideCommand, true)
        unless SUPPORTED_OVERRIDE_COMMAND_VALUE.include?(override_command)
          return append_err(
            format(
              _("Property 'overrideCommand' of component '%{name}' must be a boolean (true or false)"),
              name: component.fetch(:name)
            ),
            context
          )
        end

        return unless override_command == true && (container[:command].present? || container[:args].present?)

        append_err(
          format(
            _("Properties 'command', 'args' for component '%{name}' can only be specified " \
              "when the 'overrideCommand' attribute is set to false"),
            name: component.fetch(:name)
          ),
          context
        )
      end

      # If we support endpoints in `components` other than `container`, make changes accordingly in
      # ee/lib/remote_development/workspaces_server_operations/authorize_user_access/authorizer.rb
      # @param [Hash] context
      # @return [Hash]
      def self.validate_endpoints(context)
        devfile = context[:devfile]

        components = devfile.fetch(:components, [])
        # There is no need to append an error here since it has already been done before this code is executed.
        return context unless components.is_a?(Array)

        components.each do |component|
          # There is no need to append an error here since it has already been done before this code is executed.
          return context unless component.is_a?(Hash)

          container = component.fetch(:container, {})
          # There is no need to append an error here since it has already been done before this code is executed.
          return context unless container.is_a?(Hash)

          endpoints = container.fetch(:endpoints, [])
          return append_err(_("'Endpoints' must be an Array"), context) unless endpoints.is_a?(Array)

          endpoints.each do |endpoint|
            endpoint_name = endpoint.fetch(:name, "")
            next unless endpoint_name.downcase.start_with?(RESTRICTED_PREFIX)

            append_err(
              format(_("Endpoint name '%{endpoint}' of component '%{component}' must not start with '%{prefix}'"),
                endpoint: endpoint_name,
                component: component.fetch(:name),
                prefix: RESTRICTED_PREFIX
              ),
              context
            )
          end
        end

        context
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_commands(context)
        devfile = context[:devfile]

        commands = devfile.fetch(:commands, [])
        return append_err(_("'Commands' must be an Array"), context) unless commands.is_a?(Array)

        commands.each do |command|
          validate_command(context, command)
        end

        context
      end

      # @param [String] value
      # @param [String] type
      # @param [Hash] context
      # @param [Hash] additional_params
      # @return [Hash]
      def self.validate_command_restricted_prefix(value, type, context, additional_params = {})
        return unless value.downcase.start_with?(RESTRICTED_PREFIX)

        error_messages = {
          'command_id' => _("Command id '%{command}' must not start with '%{prefix}'"),
          'component_name' => _(
            "Component name '%{component}' for command id '%{command}' must not start with '%{prefix}'"
          ),
          'label' => _("Label '%{command_label}' for command id '%{command}' must not start with '%{prefix}'")
        }

        message_template = error_messages[type]

        params = { prefix: RESTRICTED_PREFIX }.merge(additional_params)

        case type
        when 'command_id'
          params[:command] = value
        when 'component_name'
          params[:component] = value
        when 'label'
          params[:command_label] = value
        end

        append_err(format(message_template, params), context)
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_events(context)
        devfile = context[:devfile]
        commands = devfile.fetch(:commands, [])
        events = devfile.fetch(:events, {})

        return append_err(_("'Events' must be a Hash"), context) unless events.is_a?(Hash)

        events.each do |event_type, event_type_events|
          # Ensure no event type other than "preStart" are allowed

          if SUPPORTED_EVENTS.exclude?(event_type) && event_type_events.present?
            err_msg = format(_("Event type '%{type}' is not yet supported"), type: event_type)
            # The entries for unsupported events may be defined, but they must be blank.
            append_err(err_msg, context)
          end

          # Ensure no event starts with restricted_prefix
          event_type_events.each do |command_name|
            if command_name.downcase.start_with?(RESTRICTED_PREFIX)
              append_err(
                format(_("Event '%{event}' of type '%{event_type}' must not start with '%{prefix}'"),
                  event: command_name,
                  event_type: event_type,
                  prefix: RESTRICTED_PREFIX
                ),
                context
              )
            end

            next unless event_type == :postStart

            # ===== postStart specific validations =====

            referenced_command = commands.find { |cmd| cmd[:id] == command_name }
            # Check if referenced command is defined in the command section
            unless referenced_command.is_a?(Hash)
              append_err(
                format(_("PostStart event references command '%{command}' which has no command definition."),
                  command: command_name
                ),
                context
              )
              next
            end

            # Check if the referenced command is an exec command
            next if referenced_command[:exec].present?

            append_err(
              format(_("PostStart event references command '%{command}' which is not an exec command. Only exec " \
                "commands are supported in postStart events"),
                command: command_name
              ),
              context
            )
          end
        end

        context
      end

      # @param [Hash] context
      # @return [Hash]
      def self.validate_variables(context)
        devfile = context[:devfile]

        restricted_prefix_underscore = RESTRICTED_PREFIX.tr("-", "_")

        # Ensure no variable name starts with restricted_prefix
        variables = devfile.fetch(:variables, {})

        return append_err(_("'Variables' must be a Hash"), context) unless variables.is_a?(Hash)

        variables.each_key do |variable|
          [RESTRICTED_PREFIX, restricted_prefix_underscore].each do |prefix|
            next unless variable.downcase.start_with?(prefix)

            append_err(
              format(_("Variable name '%{variable}' must not start with '%{prefix}'"),
                variable: variable,
                prefix: prefix
              ),
              context
            )
          end
        end

        context
      end

      # @param [Hash] context
      # @param [Hash] component
      # @return [Hash]
      def self.validate_component(context, component)
        return unless component.is_a?(Hash)

        append_err(_("A component must have a 'name'"), context) unless component.has_key?(:name)

        component_name = component.fetch(:name, "")
        if component_name.is_a?(String)
          # Ensure no component name starts with restricted_prefix
          if component_name.downcase.start_with?(RESTRICTED_PREFIX)
            append_err(
              format(_("Component name '%{component}' must not start with '%{prefix}'"),
                component: component_name,
                prefix: RESTRICTED_PREFIX
              ),
              context
            )
          end

          validate_volume_component_name(context, component_name) if component.has_key?(:volume)
        else
          append_err(_("'Component name' must be a String"), context)
        end

        attributes = component.fetch(:attributes, {})

        if attributes.is_a?(Hash)
          if component.dig(:attributes, :"container-overrides")
            append_err(_("Attribute 'container-overrides' is not yet supported"), context)
          end

          if component.dig(:attributes, :"pod-overrides")
            append_err(_("Attribute 'pod-overrides' is not yet supported"), context)
          end
        else
          append_err(
            format(_("'attributes' for component '%{component_name}' must be a Hash"),
              component_name: component_name), context)
        end

        # Ensure component type is supported
        UNSUPPORTED_COMPONENT_TYPES.each do |unsupported_component_type|
          if component[unsupported_component_type] # rubocop: disable Style/Next -- No need to change to next
            append_err(
              format(_("Component type '%{type}' is not yet supported"), type: unsupported_component_type),
              context
            )
          end
        end

        context
      end

      # @param [Hash] context
      # @param [Hash] command
      # @return [Hash]
      def self.validate_command(context, command)
        return append_err(_("'command' must be a Hash"), context) unless command.is_a?(Hash)

        command_id = command.fetch(:id, "")

        # Check command_id for restricted prefix
        validate_command_restricted_prefix(command_id, 'command_id', context)

        supported_command_type = SUPPORTED_COMMAND_TYPES.find { |type| command[type].present? }

        unless supported_command_type
          return append_err(
            format(_("Command '%{command}' must have one of the supported command types: %{supported_types}"),
              command: command_id,
              supported_types: SUPPORTED_COMMAND_TYPES.join(", ")
            ),
            context
          )
        end

        command_type = command[supported_command_type]

        unless command_type[:component].present?
          append_err(
            format(_("'%{type}' command '%{command}' must specify a 'component'"),
              type: supported_command_type,
              command: command_id
            ),
            context
          )
        end

        # Check component name for restricted prefix
        component_name = command_type.fetch(:component, "")

        validate_command_restricted_prefix(component_name, 'component_name', context,
          { command: command_id })

        # Check label for restricted prefix
        command_label = command_type.fetch(:label, "")

        validate_command_restricted_prefix(command_label, 'label', context,
          { command: command_id })

        # Type-specific validations for `exec` commands
        # Since we only support the exec command type for user defined poststart events
        # We don't need to have validation for other command types
        return unless supported_command_type == :exec

        exec_command = command_type

        # Validate that only the supported options are used
        unsupported_options = exec_command.keys - SUPPORTED_EXEC_COMMAND_OPTIONS
        if unsupported_options.any?
          append_err(
            format(_("Unsupported options '%{options}' for exec command '%{command}'. " \
              "Only '%{supported_options}' are supported."),
              options: unsupported_options.join(", "),
              command: command_id,
              supported_options: SUPPORTED_EXEC_COMMAND_OPTIONS.join(", ")
            ),
            context
          )
        end

        if exec_command.key?(:hotReloadCapable) && exec_command[:hotReloadCapable] != SUPPORTED_HOT_RELOAD_VALUE
          append_err(
            format(_("Property 'hotReloadCapable' for exec command '%{command}' must be false when specified"),
              command: command_id
            ),
            context
          )
        end
      end

      # @param [String] message
      # @param [Hash] context
      # @return [Hash]
      def self.append_err(message, context)
        context.fetch(:errors).append(message)

        context
      end

      # @param [Hash] context
      # @param [String] component_name
      # @return [Hash]
      def self.validate_volume_component_name(context, component_name)
        return unless component_name.length >= MAX_VOLUME_NAME_LIMIT

        details = format(_("Volume's name must be less than %{character_limit} characters"),
          character_limit: MAX_VOLUME_NAME_LIMIT
        )

        append_err(_(details), context)
      end

      private_class_method :validate_devfile_size, :validate_schema_version, :validate_parent,
        :validate_projects, :validate_root_attributes, :validate_components, :validate_containers,
        :validate_container_properties, :validate_endpoints, :validate_commands, :validate_command_restricted_prefix,
        :validate_events, :validate_variables, :validate_component, :validate_command, :append_err,
        :validate_volume_component_name
    end
  end
end
