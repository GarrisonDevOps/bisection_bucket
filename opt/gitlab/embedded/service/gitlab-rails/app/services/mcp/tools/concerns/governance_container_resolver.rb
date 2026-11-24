# frozen_string_literal: true

module Mcp
  module Tools
    module Concerns
      module GovernanceContainerResolver
        extend ActiveSupport::Concern
        include ::Gitlab::ResourceLookup
        include ::Gitlab::Utils::StrongMemoize
        include UrlParser

        DEFAULT_CONTAINER_ARGUMENTS = {
          project: :project_id,
          group: :group_id,
          project_or_group: :url
        }.freeze

        CONTAINER_KINDS = %i[project group project_or_group].freeze

        MAX_IDENTIFIERS_PER_ARGUMENT = 100

        MAX_LOOKUPS_PER_CALL = 20

        URL_VALUE = %r{\Ahttps?://}i
        NUMERIC_ID = /\A-?\d+\z/

        TooManyContainersError = Class.new(ArgumentError)

        class GovernanceContainerResolutionResult
          attr_reader :containers, :named

          def self.none
            new([], named: 0)
          end

          def initialize(containers, named:)
            @containers = Array(containers).compact
            @named = named
          end

          def none?
            named == 0
          end
        end

        class_methods do
          def ungovernable!
            @ungovernable = true
          end

          def ungovernable?
            @ungovernable == true
          end

          def container_arguments(**kinds)
            @container_arguments = DEFAULT_CONTAINER_ARGUMENTS.merge(kinds).freeze if kinds.any?

            return {} if ungovernable?

            @container_arguments || DEFAULT_CONTAINER_ARGUMENTS
          end
        end

        def ungovernable?
          self.class.ungovernable?
        end

        def container_arguments
          self.class.container_arguments
        end

        def governed_containers(arguments)
          reject_too_many_lookups!(arguments)

          identifiers = governance_identifiers_by_kind(arguments)
          result = GovernanceContainerResolutionResult.new(
            identifiers.flat_map { |kind, ids| containers_from_identifiers(kind, ids) },
            named: identifiers.values.sum(&:size)
          )

          record_resolvers.reduce(result) do |carried, (key, resolver)|
            also_governed_by(carried, arguments[key.to_sym]) { |value| run_record_resolver(resolver, value) }
          end
        end

        def declared_argument_names
          container_arguments.flat_map do |_kind, value|
            value.is_a?(Hash) ? value.keys : Array(value)
          end.map(&:to_s).uniq
        end

        def record_resolvers
          resolvers = container_arguments[:record]
          return {} unless resolvers.is_a?(Hash)

          resolvers
        end

        def run_record_resolver(resolver, value)
          instance_exec(value, &resolver)
        end

        private

        def governance_identifiers_by_kind(arguments)
          container_arguments.slice(*CONTAINER_KINDS).to_h do |kind, key|
            [kind, identifiers_from_argument(kind, key, arguments)]
          end
        end

        def reject_too_many_lookups!(arguments)
          record_resolvers.each_key { |key| reject_unexpected_list!(key, arguments) }

          keys = container_arguments.slice(*CONTAINER_KINDS).values.flat_map { |key| Array(key) }.uniq
          lookups = keys.flat_map { |key| argument_values(key, arguments) }.count { |value| per_value_lookup?(value) }
          return if lookups <= MAX_LOOKUPS_PER_CALL

          raise TooManyContainersError,
            format('A tool call cannot name more than %{max} projects or groups by path or URL',
              max: MAX_LOOKUPS_PER_CALL)
        end

        def argument_values(key, arguments)
          reject_unexpected_list!(key, arguments)

          Array(arguments[key])
        end

        def reject_unexpected_list!(key, arguments)
          return unless arguments[key].is_a?(Enumerable) && single_value_argument?(key)

          raise TooManyContainersError, format('%{key} can name only one project or group', key: key)
        end

        # The lookups run before the tool validates its input, so a list is read only where the schema allows one.
        def single_value_argument?(key)
          properties = container_argument_properties
          return false unless properties

          property = properties[key.to_s]
          !(property.is_a?(Hash) && Array(property[:type]).include?('array'))
        end

        def container_argument_properties
          return unless respond_to?(:input_schema)

          input_schema.with_indifferent_access[:properties] || {}
        rescue NoMethodError
          {}
        end
        strong_memoize_attr :container_argument_properties

        def per_value_lookup?(value)
          value = value.presence&.to_s
          return false unless value

          id = ::GlobalID.parse(value)&.model_id || value
          !NUMERIC_ID.match?(id)
        end

        def also_governed_by(result, identifier)
          return result if identifier.blank?

          containers = Array(yield(identifier)).map { |record| container_from_record(record) }
          return result if containers.any? && containers.all?(::Namespaces::UserNamespace)

          GovernanceContainerResolutionResult.new(
            result.containers + containers.grep_v(::Namespaces::UserNamespace),
            named: result.named + 1
          )
        end

        def also_governed_by_all(result, key, identifiers)
          ids = Array(identifiers).compact.presence
          return result unless ids

          reject_oversized_argument!(key, ids)

          ids = ids.uniq

          GovernanceContainerResolutionResult.new(
            result.containers + Array(yield(ids)),
            named: result.named + ids.size
          )
        end

        def record_id_from(value, expected)
          global_id = ::GlobalID.parse(value)
          return value.presence unless global_id

          global_id.model_id if global_id_matches?(global_id, expected)
        end

        def container_from_record(record)
          return record if record.is_a?(::Project)

          container_from_namespace(record)
        end

        def container_from_namespace(namespace)
          case namespace
          when ::Namespaces::ProjectNamespace then namespace.project
          when ::Group, ::Namespaces::UserNamespace then namespace
          end
        end

        def global_work_item_id?(value)
          ::GlobalID.parse(value)&.model_class == ::WorkItem
        end

        def work_item_containers(ids)
          model_ids = Array(ids).filter_map { |id| record_id_from(id, [::WorkItem, ::Issue]) }

          ::WorkItem.id_in(model_ids).map { |item| item.project || item.namespace }
        end

        def identifiers_from_argument(kind, key, arguments)
          case kind
          when :project then namespace_identifiers(key, arguments, [::Project])
          when :group then namespace_identifiers(key, arguments, [::Group])
          else namespace_identifiers(key, arguments, [::Project, ::Group])
          end
        end

        def containers_from_identifiers(kind, identifiers)
          case kind
          when :project then lookup_projects(identifiers)
          when :group then lookup_groups(identifiers)
          else projects_or_groups_from_identifiers(identifiers)
          end
        end

        def namespace_identifiers(key, arguments, expected)
          keys = Array(key).compact
          return [] if keys.empty?

          values = keys.flat_map { |k| argument_values(k, arguments) }
          reject_oversized_argument!(keys.first, values)

          values.flat_map do |value|
            value = value.presence&.to_s
            next [] unless value

            url_paths = url_identifiers(value)
            next url_paths if url_paths

            value = UrlParser.unescape_and_scrub_uri(value)
            global_id = ::GlobalID.parse(value)
            next [value] unless global_id
            next [] unless global_id_matches?(global_id, expected)

            [global_id.model_id]
          end.uniq
        end

        def reject_oversized_argument!(key, values)
          return if values.size <= MAX_IDENTIFIERS_PER_ARGUMENT

          raise TooManyContainersError,
            format('%{key} cannot name more than %{max} projects or groups',
              key: key, max: MAX_IDENTIFIERS_PER_ARGUMENT)
        end

        def url_identifiers(value)
          url = URL_VALUE.match?(value)
          paths = reference_pattern_paths(value)
          paths << generic_url_path(value) if url
          return if paths.empty? && !url

          paths.compact.uniq.map { |path| UrlParser.unescape_and_scrub_uri(path) }
        end

        def reference_pattern_paths(url)
          [::MergeRequest, ::Commit].filter_map do |klass|
            match = klass.link_reference_pattern.match(url)
            "#{match[:namespace]}/#{match[:project]}" if match
          end
        end

        def generic_url_path(url)
          parse_parent_url(url)[:path]
        rescue ArgumentError
          nil
        end

        def global_id_matches?(global_id, expected)
          expected.any? { |klass| global_id.model_class <= klass }
        rescue NameError
          false
        end

        def projects_or_groups_from_identifiers(identifiers)
          projects = lookup_projects(identifiers)
          claimed = projects.flat_map { |project| [project.id.to_s, project.full_path] }.to_set

          projects + lookup_groups(identifiers.reject { |id| claimed.include?(id) })
        end
      end
    end
  end
end
