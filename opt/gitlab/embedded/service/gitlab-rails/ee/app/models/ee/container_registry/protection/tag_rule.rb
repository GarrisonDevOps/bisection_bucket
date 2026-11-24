# frozen_string_literal: true

module EE
  module ContainerRegistry
    module Protection
      module TagRule
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        DELETE_ACTIONS = ['delete'].freeze

        prepended do
          scope :immutable, -> { where(immutable_where_conditions) }

          scope :for_actions_and_access, ->(actions, access_level, include_immutable: false) do
            conditions = base_conditions_for_actions_and_access(actions, access_level)

            if include_immutable && (actions & %w[push delete]).any?
              immutable_where_conditions.each { |column, value| conditions << arel_table[column].eq(value) }
            end

            where(conditions.reduce(:or))
          end

          scope :for_delete_and_access, ->(access_level, include_immutable: true) do
            for_actions_and_access(DELETE_ACTIONS, access_level, include_immutable:)
          end
        end

        class_methods do
          def immutable_where_conditions
            { minimum_access_level_for_push: nil, minimum_access_level_for_delete: nil }
          end
        end

        def immutable?
          !mutable?
        end

        def type
          immutable? ? 'immutable' : super
        end

        override :push_restricted?
        def push_restricted?(access_level)
          immutable? ? immutable_restriction? : super
        end

        override :delete_restricted?
        def delete_restricted?(access_level)
          immutable? ? immutable_restriction? : super
        end

        override :uniqueness_scope
        def uniqueness_scope
          immutable? ? self.class.immutable : super
        end

        private

        override :validate_access_levels
        def validate_access_levels
          if minimum_access_level_for_delete.present? ^ minimum_access_level_for_push.present?
            return errors.add(:base, _('Access levels should either both be present or both be nil'))
          end

          return unless immutable? && was_mutable?

          errors.add(:base, _('Cannot create an immutable tag rule from a protection rule'))
        end

        override :minimum_level_to_delete_rule
        def minimum_level_to_delete_rule
          immutable? ? ::Gitlab::Access::OWNER : ::Gitlab::Access::MAINTAINER
        end

        def immutable_restriction?
          project.licensed_feature_available?(:container_registry_immutable_tag_rules)
        end

        def was_mutable?
          [minimum_access_level_for_push_was, minimum_access_level_for_delete_was].all?(&:present?)
        end
      end
    end
  end
end
