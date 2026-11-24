# frozen_string_literal: true

module Tasks
  module Gitlab
    module Permissions
      module Graphql
        # Checks the types skipped with `parent_authorizes` and the fields that return them.
        #
        # A field on a type with its own token check checks the permissions the returned type
        # declares at runtime (see Types::BaseField). This class covers the fields where that
        # check does not run: fields with their own directive, root fields, mutation payloads,
        # and fields on other skipped types.
        class ParentAuthorizesCheck
          include SchemaDirectives

          Edge = Struct.new(:owner, :field)

          ROOT_TYPES = %w[Query Subscription].freeze

          # The anonymous fallback in Authz::BoundaryPolicy evaluates the declared permission
          # as a policy ability on these boundaries.
          BOUNDARY_POLICIES = { project: 'ProjectPolicy', group: 'GroupPolicy' }.freeze

          def initialize(schema)
            @schema = schema
            @types = schema.types.select { |name, type| type.is_a?(Class) && !name.start_with?('__') }
          end

          # Skipped types that declare no permissions, although a field on a type with its own
          # token check returns them.
          #
          # @return [Hash{String => Class}]
          def undeclared_types
            parent_authorizes_types.select do |name, type|
              declared_permissions(type).empty? && incoming_edges[name].any? { |edge| checked?(edge.owner) }
            end
          end

          # @return [Hash{Symbol => Array<Hash>}] violations keyed by kind
          def violations
            @violations = Hash.new { |hash, key| hash[key] = [] }

            declared_types.each do |name, type|
              declared = declared_permissions(type)

              incoming_edges[name].each { |edge| check_edge(name, type, edge, declared) }
              payload_edges[name].each { |edge| check_payload_edge(name, type, edge) }
            end

            @violations.transform_values(&:uniq)
          end

          private

          attr_reader :schema, :types

          def check_edge(name, type, edge, declared)
            field_permissions = permissions(granular_directives(edge.field))

            if field_permissions.any?
              unless declared.subset?(field_permissions)
                add(:parent_permissions_not_on_field_directive, name, type, edge, permissions: declared)
              end
            elsif root_type?(edge.owner)
              add(:unchecked_parent_authorizes_field, name, type, edge)
            elsif checked?(edge.owner)
              check_runtime_edge(name, type, edge, declared)
            else
              check_nested_edge(name, type, edge, declared)
            end
          end

          # The field checks the declared permissions on the boundary of its parent at runtime.
          def check_runtime_edge(name, type, edge, declared)
            abstract_type = mixed_abstract_type(edge.field)
            if abstract_type
              add(:inconsistent_parent_permissions, abstract_type.graphql_name, abstract_type, edge,
                declarations: declarations_of(abstract_type))
              return
            end

            owner_directives = granular_directives(edge.owner)
            boundary_types = owner_directives.filter_map { |d| d.arguments[:boundary_type] }
              .map { |boundary_type| boundary_type.downcase.to_sym }.uniq

            declared.each do |permission|
              boundary_types.each { |boundary_type| check_boundary(name, type, edge, permission, boundary_type) }
            end

            return unless edge.field.type.non_null?
            return if shares_assignable?(declared, permissions(owner_directives))

            add(:parent_permissions_on_non_null_field, name, type, edge, permissions: declared)
          end

          def check_boundary(name, type, edge, permission, boundary_type)
            assignables = ::Authz::PermissionGroups::Assignable.available_for_permission(permission)
            assignable_boundaries = assignables.flat_map(&:boundaries).map(&:to_sym).uniq

            if assignables.any? && assignable_boundaries.exclude?(boundary_type)
              add(:parent_permission_boundary_mismatch, name, type, edge,
                permission: permission, boundary_type: boundary_type, assignable_boundaries: assignable_boundaries)
            end

            policy = BOUNDARY_POLICIES[boundary_type]&.constantize
            return if policy.nil? || policy.ability_map.map.key?(permission)

            add(:parent_permission_not_a_policy_ability, name, type, edge,
              permission: permission, boundary_type: boundary_type)
          end

          # Nothing checks a field on another skipped type at runtime, so every path to it
          # has to check the declared permissions further up.
          def check_nested_edge(name, type, edge, declared)
            return if paths_check?(edge, declared, Set[name])

            add(:parent_permissions_missing_on_path, name, type, edge, permissions: declared)
          end

          def check_payload_edge(name, type, edge)
            return if mutation_checked?(edge.owner.mutation)

            add(:unchecked_parent_authorizes_field, name, type, edge)
          end

          # The mutation authorizes the records its payload returns, so it needs a real token check.
          # A mutation without a directive is listed in the todo file and denies granular tokens.
          def mutation_checked?(mutation)
            directives = granular_directives(mutation)
            directives.empty? || directives.any? { |directive| directive.arguments[:skip_reason].blank? }
          end

          # A field that returns an interface or union checks the permissions before its resolver
          # picks the concrete type, so it checks nothing when the possible types declare different ones.
          def mixed_abstract_type(field)
            returned = field.type.unwrap
            returned = returned.node_type if wrapper_type?(returned)
            returned if returned.kind.abstract? && declarations_of(returned).values.uniq.size > 1
          end

          def declarations_of(abstract_type)
            schema.possible_types(abstract_type).to_h do |possible|
              [possible.graphql_name, declared_permissions(possible).to_a.sort]
            end
          end

          # Whether every path through the field checks the missing permissions.
          def paths_check?(edge, missing, visited)
            missing -= permissions(granular_directives(edge.field))
            return true if missing.empty?

            owner = edge.owner
            return false if root_type?(owner)
            return mutation_checked?(owner.mutation) if payload_type?(owner)

            directives = granular_directives(owner)
            return missing.subset?(permissions(directives)) unless pass_through?(owner, directives)
            return true if visited.include?(owner.graphql_name)

            missing -= declared_permissions(owner)
            visited |= [owner.graphql_name]
            (incoming_edges[owner.graphql_name] + payload_edges[owner.graphql_name])
              .all? { |owner_edge| paths_check?(owner_edge, missing, visited) }
          end

          def shares_assignable?(declared, owner_permissions)
            declared.all? do |permission|
              ::Authz::PermissionGroups::Assignable.available_for_permission(permission).any? do |assignable|
                assignable.permissions.intersect?(owner_permissions.to_a)
              end
            end
          end

          def checked?(type)
            directives = granular_directives(type)
            directives.any? && directives.none? { |directive| directive.arguments[:skip_reason].present? }
          end

          def pass_through?(owner, directives)
            wrapper_type?(owner) || skip_directive(directives).present?
          end

          # Payload fields are checked separately, and a type without any directive denies
          # fine-grained tokens.
          def ignored_owner?(owner)
            return true if payload_type?(owner)
            return false if root_type?(owner) || wrapper_type?(owner)

            granular_directives(owner).empty?
          end

          def declared_types
            parent_authorizes_types.select { |_, type| declared_permissions(type).any? }
          end

          def parent_authorizes_types
            @parent_authorizes_types ||= skipped_types.select do |_, type|
              skip_directive(granular_directives(type)).arguments[:skip_reason].to_sym == :parent_authorizes
            end
          end

          def skipped_types
            @skipped_types ||= types.select do |name, type|
              graphql_object_type?(name, type) && skip_directive(granular_directives(type))
            end
          end

          def incoming_edges
            @incoming_edges ||= edges_from(types.values.reject { |owner| ignored_owner?(owner) })
          end

          def payload_edges
            @payload_edges ||= edges_from(types.values.select { |owner| payload_type?(owner) })
          end

          def edges_from(owners)
            Hash.new { |hash, key| hash[key] = [] }.tap do |edges|
              owners.each do |owner|
                next unless owner.kind.object?

                owner.fields.each_value do |field|
                  field_targets(owner, field).each { |target| edges[target] << Edge.new(owner, field) }
                end
              end
            end
          end

          # A field returning a connection reaches both the connection, for its own
          # fields, and its node type, which is reported under the field's name.
          def field_targets(owner, field)
            type = field.type.unwrap
            return [] if wrapper_type?(owner) && %w[nodes node].include?(field.name)

            candidates = [type]
            candidates << type.node_type if wrapper_type?(type) && !wrapper_type?(owner)
            candidates = candidates.flat_map { |t| t.kind.abstract? ? schema.possible_types(t) : [t] }

            candidates.map(&:graphql_name).select do |name|
              skipped_types.key?(name) || wrapper_type?(types[name])
            end
          end

          def wrapper_type?(type)
            type.is_a?(Class) &&
              (type < GraphQL::Types::Relay::ConnectionBehaviors || type < GraphQL::Types::Relay::EdgeBehaviors)
          end

          def root_type?(type)
            ROOT_TYPES.include?(type.graphql_name)
          end

          def payload_type?(type)
            type.respond_to?(:mutation) && type.mutation.present?
          end

          def skip_directive(directives)
            directives.find { |directive| directive.arguments[:skip_reason].present? }
          end

          def declared_permissions(type)
            skip = skip_directive(granular_directives(type))
            return Set.new unless skip

            normalize(skip.arguments[:parent_authorizes])
          end

          def permissions(directives)
            normalize(directives.flat_map { |directive| Array(directive.arguments[:permissions]) })
          end

          def normalize(permissions)
            Array(permissions).to_set { |permission| permission.to_s.downcase.to_sym }
          end

          def add(kind, name, type, edge, **details)
            @violations[kind] << {
              kind: 'type', name: name, source: class_source_path(type),
              field: "#{edge.owner.graphql_name}.#{edge.field.name}"
            }.merge(details)
          end
        end
      end
    end
  end
end
