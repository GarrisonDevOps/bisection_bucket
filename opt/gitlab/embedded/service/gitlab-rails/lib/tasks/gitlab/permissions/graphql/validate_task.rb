# frozen_string_literal: true

module Tasks
  module Gitlab
    module Permissions
      module Graphql
        class ValidateTask < ::Tasks::Gitlab::Permissions::BaseValidateTask
          include SchemaDirectives

          TODO_FILE = Rails.root.join('config/authz/graphql/authorization_todo.txt')
          VALID_SKIP_REASONS = SkipReasons::VALID_SKIP_REASONS
          PARENT_AUTHORIZES_ENTRY = 'parent_authorizes'
          PARENT_AUTHORIZES_KINDS = %i[
            undeclared_parent_permissions
            parent_permissions_not_on_field_directive
            unchecked_parent_authorizes_field
            parent_permission_boundary_mismatch
            parent_permission_not_a_policy_ability
            parent_permissions_on_non_null_field
            parent_permissions_missing_on_path
            inconsistent_parent_permissions
          ].freeze

          def initialize
            @violations = {
              boundary_mismatch: [],
              invalid_permission: [],
              missing_authorization: [],
              invalid_skip_reason: [],
              conflicting_authorization: [],
              invalid_condition: []
            }.merge(PARENT_AUTHORIZES_KINDS.index_with { [] })
          end

          private

          attr_reader :violations

          def validate!
            each_type_with_directives do |item, directives|
              directives.each { |directive| validate_granular_directive(item, directive) }
              validate_skip(item, directives)
            end

            each_mutation_directive { |item, directive| validate_granular_directive(item, directive) }
            each_field_directive { |item, directive| validate_granular_directive(item, directive) }

            violations.merge!(parent_authorizes_check.violations) { |_, own, found| own + found }

            (current_todo_entries - load_todo_entries).each do |entry|
              kind, name = entry.split(':', 2)
              item = { kind: kind, name: name, source: current_entry_sources[entry] }

              if kind == PARENT_AUTHORIZES_ENTRY
                violations[:undeclared_parent_permissions] << item.merge(kind: 'type')
              else
                violations[:missing_authorization] << item
              end
            end

            super
          end

          def validate_granular_directive(item, directive)
            return if directive.arguments[:skip_reason].present?

            validate_conditions(item, directive)

            permissions = directive.arguments[:permissions].map { |p| p.to_s.downcase.to_sym }
            boundary_type = directive.arguments[:boundary_type]&.to_sym

            permissions.each do |permission|
              validate_permission_exists(item, permission)
              validate_boundary_type(item, permission, boundary_type)
            end
          end

          def validate_conditions(item, directive)
            unknown = Array(directive.arguments[:assignable_when]).map(&:to_sym) - known_conditions
            return if unknown.empty?

            violations[:invalid_condition] << item.merge(reason: unknown.join(', '))
          end

          def known_conditions
            @known_conditions ||= ::Authz::PermissionGroups::AssignableCondition::EVALUATORS.keys
          end

          def validate_skip(item, directives)
            skip_directive = directives.find { |directive| directive.arguments[:skip_reason].present? }
            return unless skip_directive

            skip_item = item.merge(
              reason: skip_directive.arguments[:skip_reason].to_sym,
              has_granular: directives.any? { |directive| directive.arguments[:permissions].present? }
            )

            validate_skip_reason(skip_item)
            validate_no_conflict(skip_item)

            Array(skip_directive.arguments[:parent_authorizes]).each do |permission|
              validate_permission_exists(item, permission.to_s.downcase.to_sym)
            end
          end

          def current_todo_entries
            @current_todo_entries ||= current_entry_sources.keys.to_set
          end

          def current_entry_sources
            @current_entry_sources ||= {}.tap do |entries|
              GitlabSchema.types['Mutation'].fields.each do |field_name, field|
                resolver = resolve_mutation_class(field)
                next unless resolver

                name = mutation_name_for(field_name, resolver)
                entries["mutation:#{name}"] = class_source_path(resolver) if find_mutation_directives(field,
                  resolver).empty?
              end

              GitlabSchema.types.each do |name, type|
                next unless graphql_object_type?(name, type)

                next if type.directives.any?(Directives::Authz::GranularScope)

                entries["type:#{name}"] = class_source_path(type)
              end

              parent_authorizes_check.undeclared_types.each do |name, type|
                entries["#{PARENT_AUTHORIZES_ENTRY}:#{name}"] = class_source_path(type)
              end
            end
          end

          def parent_authorizes_check
            @parent_authorizes_check ||= ParentAuthorizesCheck.new(GitlabSchema)
          end

          def validate_skip_reason(item)
            return if VALID_SKIP_REASONS.include?(item[:reason])

            violations[:invalid_skip_reason] << item
          end

          def validate_no_conflict(item)
            return unless item[:has_granular]

            violations[:conflicting_authorization] << item
          end

          def todo_file_label
            'GraphQL'
          end

          def valid_permissions
            @valid_permissions ||= Authz::PermissionGroups::Assignable.available_permissions.to_set
          end

          def validate_permission_exists(item, permission)
            return if valid_permissions.include?(permission)

            violations[:invalid_permission] << item.merge(permission: permission)
          end

          def validate_boundary_type(item, permission, boundary_type)
            return unless boundary_type

            assignables = Authz::PermissionGroups::Assignable.available_for_permission(permission)
            return if assignables.empty?

            assignable_boundaries = assignables.flat_map(&:boundaries).uniq.map(&:to_sym)
            return if assignable_boundaries.include?(boundary_type)

            violations[:boundary_mismatch] << item.merge(
              permission: permission,
              boundary_type: boundary_type,
              assignable_boundaries: assignable_boundaries
            )
          end

          def format_all_errors
            format_graphql_errors(:invalid_permission) +
              format_boundary_mismatch_errors +
              format_missing_authorization_errors +
              format_invalid_skip_reason_errors +
              format_conflicting_authorization_errors +
              format_graphql_errors(:invalid_condition) +
              PARENT_AUTHORIZES_KINDS.sum('') { |kind| format_parent_authorizes_errors(kind) }
          end

          def format_graphql_errors(kind)
            return '' if violations[kind].empty?

            out = "#{error_messages[kind]}\n\n"

            violations[kind].each do |v|
              out += "  - [#{v[:kind]}] #{v[:name]}: #{v[:permission] || v[:reason]} (#{v[:source]})\n"
            end

            "#{out}\n"
          end

          def format_boundary_mismatch_errors
            return '' if violations[:boundary_mismatch].empty?

            out = "#{error_messages[:boundary_mismatch]}\n\n"

            violations[:boundary_mismatch].each do |v|
              out += "  - [#{v[:kind]}] #{v[:name]}: #{v[:permission]} (#{v[:source]})\n"
              out += "      Directive boundary_type: #{v[:boundary_type]}\n"
              out += "      Assignable boundaries: #{v[:assignable_boundaries].join(', ')}\n"
            end

            "#{out}\n"
          end

          def format_missing_authorization_errors
            return '' if violations[:missing_authorization].empty?

            out = "#{error_messages[:missing_authorization]}\n\n"

            violations[:missing_authorization].each do |v|
              out += "  - [#{v[:kind]}] #{v[:name]} (#{v[:source]})\n"
            end

            "#{out}\n"
          end

          def format_invalid_skip_reason_errors
            return '' if violations[:invalid_skip_reason].empty?

            out = "#{error_messages[:invalid_skip_reason]}\n\n"

            violations[:invalid_skip_reason].each do |v|
              out += "  - [#{v[:kind]}] #{v[:name]}: #{v[:reason]} (#{v[:source]})\n"
            end

            "#{out}\n"
          end

          def format_conflicting_authorization_errors
            return '' if violations[:conflicting_authorization].empty?

            out = "#{error_messages[:conflicting_authorization]}\n\n"

            violations[:conflicting_authorization].each do |v|
              out += "  - [#{v[:kind]}] #{v[:name]} (#{v[:source]})\n"
            end

            "#{out}\n"
          end

          def format_parent_authorizes_errors(kind)
            return '' if violations[kind].empty?

            out = "#{error_messages[kind]}\n\n"

            violations[kind].each do |v|
              out += "  - [#{v[:kind]}] #{v[:name]} (#{v[:source]})\n"
              out += parent_authorizes_details(v).map { |line| "      #{line}\n" }.join
            end

            "#{out}\n"
          end

          def parent_authorizes_details(violation)
            details = []
            details << "Field: #{violation[:field]}" if violation[:field]
            details << "Permissions: #{violation[:permissions].to_a.join(', ')}" if violation[:permissions]
            details << "Permission: #{violation[:permission]} on #{violation[:boundary_type]}" if violation[:permission]
            boundaries = violation[:assignable_boundaries]
            details << "Assignable boundaries: #{boundaries.join(', ')}" if boundaries

            violation[:declarations]&.each do |type, permissions|
              details << "#{type}: #{permissions.join(', ').presence || 'none'}"
            end

            details
          end

          def error_messages
            {
              invalid_permission: <<~MSG.chomp,
                The following GraphQL types/mutations/fields reference permissions not included in any assignable permission.
                Add the permission to an assignable permission group in config/authz/permission_groups/assignable_permissions/.
                #{assignable_permissions_link(anchor: 'create-the-assignable-permission-file')}
              MSG
              boundary_mismatch: <<~MSG.chomp,
                The following GraphQL types/mutations/fields have a boundary_type that doesn't match the assignable permission boundaries.
                Update the assignable permission to include the directive's boundary_type, or fix the directive's boundary_type.
                #{assignable_permissions_link(anchor: 'determining-boundaries')}
              MSG
              missing_authorization: <<~MSG.chomp,
                The following GraphQL mutations and/or types are missing granular token authorization.
                Add `authorize_granular_token` with permissions and boundary_type to the mutation or type.
                #{graphql_implementation_guide_link}
              MSG
              invalid_skip_reason: <<~MSG.chomp,
                The following GraphQL types use a missing or invalid `authorize_granular_token` skip_reason.
                Use one of: #{VALID_SKIP_REASONS.map { |r| ":#{r}" }.join(', ')}
              MSG
              conflicting_authorization: <<~MSG.chomp,
                The following GraphQL types declare `authorize_granular_token` with both permissions and a skip_reason.
                Remove one: a type is either authorized directly or intentionally skipped.
              MSG
              invalid_condition: <<~MSG.chomp,
                The following GraphQL types/mutations/fields use an unknown assignable_when condition.
                Use one of: #{::Authz::PermissionGroups::AssignableCondition::EVALUATORS.keys.map { |c| ":#{c}" }.join(', ')}
                #{assignable_permissions_link(anchor: 'conditionally-assignable-permissions')}
              MSG
              undeclared_parent_permissions: <<~MSG.chomp,
                The following GraphQL types skip granular token authorization with `parent_authorizes`,
                and a type with its own granular token check returns them, but they declare no permission.
                Replace `skip_reason: :parent_authorizes` with `parent_authorizes: :permission_name`.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              parent_permissions_not_on_field_directive: <<~MSG.chomp,
                The following fields have their own granular token directive and return a type declared with
                `parent_authorizes:`, but the directive does not include the type's permissions.
                Add them to the field's directive.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              unchecked_parent_authorizes_field: <<~MSG.chomp,
                The following root fields or mutation payload fields return a type declared with
                `parent_authorizes:`, but nothing checks a granular token for them.
                Give a root field a directive that includes the type's permissions.
                Give a mutation its own granular token check.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              parent_permission_boundary_mismatch: <<~MSG.chomp,
                The following fields check a type's `parent_authorizes:` permission on a boundary
                that the permission's assignable permissions do not include.
                Add the boundary to the assignable permission, or give the field its own directive.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              parent_permission_not_a_policy_ability: <<~MSG.chomp,
                The following fields check a type's `parent_authorizes:` permission on a project or group,
                but the permission is not an ability of that policy. On public projects and groups,
                granular tokens get the permissions anonymous users have, so the permission must be a policy ability.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              parent_permissions_on_non_null_field: <<~MSG.chomp,
                The following non-null fields return a type whose `parent_authorizes:` permission is not in an
                assignable permission with the parent's permission. A denied check would null the parent.
                Make the field nullable, or add the permission to the parent's assignable permission.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              parent_permissions_missing_on_path: <<~MSG.chomp,
                The following fields of a skipped type return a type declared with `parent_authorizes:`,
                but a path to the field does not check the type's permissions, or passes through a mutation
                without its own granular token check. Add a directive with the permissions to the field.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
              inconsistent_parent_permissions: <<~MSG.chomp
                The following fields have no directive of their own and return an interface or union whose
                possible types declare different `parent_authorizes:` permissions, so the fields check none of them.
                Give the field a directive that includes the permissions, or declare the same permissions
                on all possible types.
                #{graphql_implementation_guide_link(anchor: 'declare-the-permission-of-a-type-that-relies-on-its-parent')}
              MSG
            }
          end

          def print_success_message
            puts "GraphQL permissions are valid"
          end

          def json_schema_file
            nil
          end
        end
      end
    end
  end
end
