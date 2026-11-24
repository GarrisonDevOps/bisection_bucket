# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class Upstream
        class Rule < ApplicationRecord
          WILDCARD_PATTERN_FORMATS = {
            group_id: {
              with: Gitlab::Regex::VirtualRegistries::Packages::Upstreams::Rules.maven_app_group_wildcard_pattern_regex,
              message: ->(*) { _('should be a valid Maven group ID with optional wildcard characters.') }
            },
            artifact_id: {
              with: Gitlab::Regex::VirtualRegistries::Packages::Upstreams::Rules.maven_app_name_wildcard_pattern_regex,
              message: ->(*) { _('should be a valid Maven artifact ID with optional wildcard characters.') }
            },
            version: {
              with: Gitlab::Regex::VirtualRegistries::Packages::Upstreams::Rules.maven_version_wildcard_pattern_regex,
              message: ->(*) { _('should be a valid Maven version with optional wildcard characters.') }
            }
          }.freeze

          MAX_RULES_PER_UPSTREAM = 20

          belongs_to :group, optional: false
          belongs_to :remote_upstream,
            class_name: 'VirtualRegistries::Packages::Maven::Upstream',
            inverse_of: :rules,
            optional: false

          enum :pattern_type, { wildcard: 0, regex: 1 }, prefix: true
          enum :rule_type, { allow: 0, deny: 1 }, prefix: true
          enum :target_coordinate, { group_id: 0, artifact_id: 1, version: 2 }, prefix: true

          validates :group, top_level_group: true
          validates :pattern, presence: true, length: { maximum: 255 },
            uniqueness: { scope: %i[remote_upstream_id pattern_type rule_type target_coordinate] }
          validates :pattern_type, presence: true
          validates :rule_type, presence: true
          validates :target_coordinate, presence: true
          validates :pattern, untrusted_regexp: true, if: :pattern_type_regex?

          validates :pattern, format: WILDCARD_PATTERN_FORMATS[:group_id],
            if: -> { pattern_type_wildcard? && target_coordinate_group_id? }
          validates :pattern, format: WILDCARD_PATTERN_FORMATS[:artifact_id],
            if: -> { pattern_type_wildcard? && target_coordinate_artifact_id? }
          validates :pattern, format: WILDCARD_PATTERN_FORMATS[:version],
            if: -> { pattern_type_wildcard? && target_coordinate_version? }

          validate :validate_max_rules_per_upstream, on: :create, if: :remote_upstream

          scope :allowed, -> { where(rule_type: :allow) }
          scope :denied, -> { where(rule_type: :deny) }

          def self.declarative_policy_class
            'VirtualRegistries::Policies::GroupPolicy'
          end

          def self.rules_count_by_upstream_ids(upstream_ids)
            return {} if upstream_ids.blank?

            where(remote_upstream_id: upstream_ids)
              .group(:remote_upstream_id)
              .count
          end

          private

          def validate_max_rules_per_upstream
            return if self.class.where(remote_upstream:).size < MAX_RULES_PER_UPSTREAM

            errors.add(:base, "Maximum of #{MAX_RULES_PER_UPSTREAM} rules per upstream has been reached")
          end
        end
      end
    end
  end
end
