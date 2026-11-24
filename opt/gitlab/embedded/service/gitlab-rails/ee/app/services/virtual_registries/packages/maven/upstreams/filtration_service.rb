# frozen_string_literal: true

# Service to evaluate allow/deny filtration rules for Maven upstreams.
#
# This service evaluates filtration rules against a Maven artifact's relative path
# and returns the upstreams that should be allowed.
#
# Precedence rules:
# 1. Deny patterns always take precedence - if any deny rule matches, the upstream is denied
# 2. If no allow patterns exist for a coordinate, it's allowed by default
# 3. If allow patterns exist for a coordinate, at least one must match
#
# The pattern matching is performed in the database using:
# - ILIKE operator for wildcard patterns (via Gitlab::SQL::Glob)
# - ~* operator for regex patterns (PostgreSQL regex matching)
#
# @example
#   service = VirtualRegistries::Packages::Maven::Upstreams::FiltrationService.new(
#     upstreams: [upstream1, upstream2, upstream3],
#     relative_path: 'com/example/my-app/1.0.0/my-app-1.0.0.jar'
#   )
#   result = service.execute
#   result[:allowed_upstreams] => [upstream1, upstream3]

module VirtualRegistries
  module Packages
    module Maven
      module Upstreams
        class FiltrationService
          include Gitlab::Utils::StrongMemoize

          SLASH = '/'
          SNAPSHOT_TERM = '-SNAPSHOT'
          NO_UPSTREAMS_ERROR = 'No upstreams were provided.'
          NO_RELATIVE_PATH_ERROR = 'Relative path is required for upstream filtration.'
          NO_COORDINATES_ERROR = 'No Maven coordinates could be extracted from the relative path.'

          def initialize(upstreams:, relative_path:)
            @upstreams = upstreams
            @relative_path = relative_path
          end

          def execute
            return ServiceResponse.error(message: NO_UPSTREAMS_ERROR) if upstreams.blank?
            return ServiceResponse.error(message: NO_RELATIVE_PATH_ERROR) if relative_path.blank?
            return ServiceResponse.error(message: NO_COORDINATES_ERROR) if coordinates.empty?

            denied_id_set = denied_ids.to_set
            allowed_upstreams, denied_upstreams = upstreams.partition { |u| denied_id_set.exclude?(u.id) }
            ServiceResponse.success(payload: { allowed_upstreams:, denied_upstreams: })
          end

          private

          attr_reader :upstreams, :relative_path

          def coordinates
            path, _, file_name = relative_path.rpartition(SLASH)

            if metadata_file?(path, file_name)
              package_name = path
              version = nil
            else
              package_name, _, version = path.rpartition(SLASH)
            end

            group_id, _, artifact_id = package_name.rpartition(SLASH)
            group_id.tr!(SLASH, '.')

            { group_id:, artifact_id:, version: }.compact_blank
          end
          strong_memoize_attr :coordinates

          def metadata_file?(path, file_name)
            file_name == ::Packages::Maven::Metadata.filename && !path&.ends_with?(SNAPSHOT_TERM)
          end

          # rubocop:disable CodeReuse/ActiveRecord -- highly specific query
          def denied_ids
            rules_table
              .where(remote_upstream_id: upstreams.map(&:id), target_coordinate: coordinate_enums.keys)
              .group(:remote_upstream_id, :target_coordinate)
              .having(denied_for_coordinate_expression)
              .pluck(:remote_upstream_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- each upstream has max 20 rules
          end
          # rubocop:enable CodeReuse/ActiveRecord

          def denied_for_coordinate_expression
            case_clause = Arel::Nodes::Case.new(rules_arel[:target_coordinate])

            coordinate_enums.reduce(case_clause) do |node, (enum_value, coordinate_value)|
              node.when(enum_value).then(denied_expression(coordinate_value))
            end.else(false)
          end

          def denied_expression(value)
            pattern_match = pattern_match_expression(value)

            is_deny = rules_arel[:rule_type].eq(rules_table.rule_types[:deny])
            is_allow = rules_arel[:rule_type].eq(rules_table.rule_types[:allow])

            has_matching_deny = bool_or(is_deny.and(pattern_match))
            has_any_allow = bool_or(is_allow)
            has_matching_allow = bool_or(is_allow.and(pattern_match))

            # Denied if: has matching deny rule OR (has allow rules but none match)
            Arel::Nodes::Case.new
              .when(has_matching_deny).then(true)
              .when(has_any_allow.and(has_matching_allow.not)).then(true)
              .else(false)
          end

          def pattern_match_expression(value)
            quoted_value = Arel::Nodes.build_quoted(value)

            Arel::Nodes::Case.new(rules_arel[:pattern_type])
              .when(rules_table.pattern_types[:wildcard])
              .then(quoted_value.matches(Arel.sql(::Gitlab::SQL::Glob.to_like(rules_arel[:pattern].name))))
              .when(rules_table.pattern_types[:regex])
              .then(quoted_value.matches_regexp(rules_arel[:pattern], false))
              .else(false)
          end

          def coordinate_enums
            @coordinate_enums ||= coordinates.transform_keys { |coord| rules_table.target_coordinates[coord] }
          end

          def rules_table
            ::VirtualRegistries::Packages::Maven::Upstream::Rule
          end

          def rules_arel
            rules_table.arel_table
          end

          def bool_or(expression)
            Arel::Nodes::NamedFunction.new('bool_or', [expression])
          end
        end
      end
    end
  end
end
