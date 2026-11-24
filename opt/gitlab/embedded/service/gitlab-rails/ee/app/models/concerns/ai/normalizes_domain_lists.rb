# frozen_string_literal: true

module Ai
  module NormalizesDomainLists
    extend ActiveSupport::Concern

    MAX_DOMAINS_PER_LIST = 500
    MAX_DOMAIN_LENGTH = 253
    DOMAIN_LIST_ATTRIBUTES = %i[allowed_domains denied_domains].freeze

    included do
      before_validation :normalize_domain_lists
      validate :validate_domain_list_limits
    end

    private

    def normalize_domain_lists
      self.allowed_domains = allowed_domains&.map(&:downcase)
      self.denied_domains = denied_domains&.map(&:downcase)
    end

    # Only growth and newly added domains are checked, so lists saved before the limits existed can still shrink.
    def validate_domain_list_limits
      changes = DOMAIN_LIST_ATTRIBUTES
        .select { |attribute| will_save_change_to_attribute?(attribute) }
        .map { |attribute| attribute_change_to_be_saved(attribute).map(&:to_a) }

      too_many = changes.any? do |previous_domains, domains|
        domains.size > MAX_DOMAINS_PER_LIST && domains.size > previous_domains.size
      end

      too_long = changes.any? do |previous_domains, domains|
        (domains - previous_domains).any? { |domain| domain.length > MAX_DOMAIN_LENGTH }
      end

      if too_many
        errors.add(:base, format(
          n_('Each domain list can contain at most %{count} domain.',
            'Each domain list can contain at most %{count} domains.', MAX_DOMAINS_PER_LIST),
          count: MAX_DOMAINS_PER_LIST
        ))
      end

      return unless too_long

      errors.add(:base, format(
        n_('Each domain can be at most %{count} character long.',
          'Each domain can be at most %{count} characters long.', MAX_DOMAIN_LENGTH),
        count: MAX_DOMAIN_LENGTH
      ))
    end
  end
end
