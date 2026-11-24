# frozen_string_literal: true

module Ai
  module Catalog
    # Validates the config of a foundational flow's `concurrency` (a `FoundationalFlow::Concurrency`):
    # nil, or a Hash of `live_statuses` (required), `revision_resolver`, `supersede` and
    # `feature_flag`. Errors on a key are added as `concurrency.<key>`.
    class ConcurrencyValidator < ActiveModel::EachValidator
      KEYS = %i[live_statuses revision_resolver supersede feature_flag].freeze

      def validate_each(record, attribute, concurrency)
        value = concurrency&.config
        return if value.nil?
        return record.errors.add(attribute, 'must be a Hash') unless value.is_a?(Hash)

        non_symbols = value.keys.reject { |key| key.is_a?(Symbol) }
        return record.errors.add(attribute, "keys must be Symbols: #{non_symbols.join(', ')}") if non_symbols.any?

        unknown = value.keys - KEYS
        record.errors.add(attribute, "contains unknown keys: #{unknown.join(', ')}") if unknown.any?

        validate_live_statuses(record, :"#{attribute}.live_statuses", value[:live_statuses])
        validate_revision_resolver(record, :"#{attribute}.revision_resolver", value[:revision_resolver])
        validate_supersede(record, :"#{attribute}.supersede", value)
        validate_feature_flag(record, :"#{attribute}.feature_flag", value[:feature_flag])
      end

      private

      def validate_live_statuses(record, key, statuses)
        return record.errors.add(key, 'must be a non-empty Array') unless statuses.is_a?(Array) && statuses.any?

        known = ::Ai::DuoWorkflows::Workflow.state_machines[:status].states.map(&:name)
        unknown = statuses.map { |status| status.to_s.to_sym } - known
        record.errors.add(key, "contains unknown statuses: #{unknown.join(', ')}") if unknown.any?
      end

      def validate_revision_resolver(record, key, resolver)
        ResolverValidator.new(attributes: [key], keywords: [:resource]).validate_each(record, key, resolver)
      end

      def validate_supersede(record, key, value)
        supersede = value[:supersede]
        return if supersede.nil?
        return record.errors.add(key, 'must be true or false') unless [true, false].include?(supersede)

        record.errors.add(key, 'needs a revision_resolver') if supersede && value[:revision_resolver].nil?
      end

      def validate_feature_flag(record, key, flag)
        return if flag.nil?
        return if (flag.is_a?(String) || flag.is_a?(Symbol)) && flag.present?

        record.errors.add(key, 'must be the name of a feature flag')
      end
    end
  end
end
