# frozen_string_literal: true

module Mcp
  module Tools
    module Projects
      class SaveProjectService < Base::AggregatedService
        include Gitlab::Utils::Override

        CREATE_PARAMS = ::API::Helpers::ProjectsHelpers.create_project_mcp_params.freeze

        register_version '0.1.0', {
          toolset: :core,
          description: <<~DESC.strip,
            Create a new GitLab project.

            Creates a project in the specified namespace (group or user). If no namespace is
            provided, the project is created in the authenticated user's personal namespace.
          DESC
          annotations: {
            title: 'Create project',
            readOnlyHint: false,
            destructiveHint: false,
            idempotentHint: false,
            openWorldHint: true
          },
          input_schema: {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                description: 'Name of the project. Required.'
              },
              path: {
                type: 'string',
                description: 'URL slug for the project.'
              },
              namespace_id: {
                type: 'integer',
                description: 'ID of the namespace (group or user) to create the project in.'
              },
              namespace_path: {
                type: 'string',
                description: 'Full path of the namespace. Alternative to namespace_id; provide one.'
              },
              description: {
                type: 'string',
                description: 'Description of the project.'
              },
              visibility: {
                type: 'string',
                enum: %w[private internal public],
                description: 'Visibility level.'
              },
              initialize_with_readme: {
                type: 'boolean',
                description: 'Create an initial README.md file.'
              },
              default_branch: {
                type: 'string',
                description: 'Default branch name.'
              },
              topics: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of topics (tags) for the project.'
              },
              template_name: {
                type: 'string',
                description: 'Name of a built-in project template, for example "rails", "spring", or "express".'
              }
            },
            required: ['name']
          }
        }

        override :tool_name
        def self.tool_name
          'save_project'
        end

        container_arguments record: {
          namespace_id: ->(id) { ::Namespace.without_project_namespaces.find_by_id(id) },
          namespace_path: ->(path) {
            ::Namespace.without_project_namespaces.find_by_full_path(
              Mcp::Tools::Concerns::UrlParser.unescape_and_scrub_uri(path))
          }
        }

        protected

        override :transform_arguments
        def transform_arguments(args)
          args = args.dup
          resolve_namespace(args)
          args.slice(*CREATE_PARAMS)
        end

        override :select_tool
        def select_tool(_args)
          tools.find { |tool| tool.name.to_sym == :create_project }
        end

        private

        def resolve_namespace(args)
          if args.key?(:namespace_path)
            raise ArgumentError, 'Provide namespace_path or namespace_id, not both.' if args.key?(:namespace_id)

            args[:namespace_id] = namespace_id_from_path(args.delete(:namespace_path))
          elsif args.key?(:namespace_id)
            validate_namespace_id!(args[:namespace_id])
          end

          args
        end

        def validate_namespace_id!(id)
          namespace = Namespace.find_by_id(id)
          raise ArgumentError, "Namespace '#{id}' not found or inaccessible." unless readable?(namespace)
        end

        def namespace_id_from_path(path)
          path = Mcp::Tools::Concerns::UrlParser.unescape_and_scrub_uri(path)

          namespace = Namespace.find_by_full_path(path)
          raise ArgumentError, "Namespace '#{path}' not found or inaccessible." unless readable?(namespace)

          namespace.id
        end

        def readable?(namespace)
          namespace && Ability.allowed?(current_user, :read_namespace_via_membership, namespace)
        end
      end
    end
  end
end

Mcp::Tools::Projects::SaveProjectService.prepend_mod
