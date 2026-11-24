# frozen_string_literal: true

module GitlabSubscriptions
  class AddOn < ApplicationRecord
    validates :name,
      presence: true,
      uniqueness: true
    validates :description,
      presence: true,
      length: { maximum: 512 }

    enum :name, {
      code_suggestions: 1,
      # 2 was product_analytics, removed in 19.4
      duo_enterprise: 3,
      duo_amazon_q: 4,
      duo_core: 5,
      self_hosted_dap: 6,
      gitlab_credits: 7,
      secrets_manager: 8,
      flex_offline: 9,
      orbit_promo: 10
    }

    DUO_ADD_ONS = %i[code_suggestions duo_enterprise duo_amazon_q duo_core self_hosted_dap gitlab_credits].freeze

    SEAT_ASSIGNABLE_DUO_ADD_ONS = %w[code_suggestions duo_enterprise].freeze

    scope :duo_add_ons, -> { where(name: DUO_ADD_ONS) }
    scope :seat_assignable_duo_add_ons, -> { where(name: SEAT_ASSIGNABLE_DUO_ADD_ONS) }

    def self.uids_for_names(add_on_names)
      Array.wrap(add_on_names).filter_map { |name| names[name.to_s] }
    end

    # Note: If a new enum is added, make sure to update this method to reflect that as well.
    def self.descriptions
      {
        code_suggestions: 'Add-on for GitLab Duo Pro.',
        duo_enterprise: 'Add-on for GitLab Duo Enterprise.',
        duo_amazon_q: 'Add-on for GitLab Duo with Amazon Q.',
        duo_core: 'Add-on for GitLab Duo Core.',
        self_hosted_dap: 'Add-on for GitLab Duo Agent Platform Self-Hosted.',
        gitlab_credits: 'Add-on for GitLab Credits.',
        secrets_manager: 'Add-on for GitLab Secrets Manager.',
        flex_offline: 'Add-on for GitLab Flex Offline.',
        orbit_promo: 'Add-on for GitLab Orbit Promotional ELA.'
      }
    end

    def self.find_or_create_by_name(add_on_name)
      create_with(description: GitlabSubscriptions::AddOn.descriptions[add_on_name.to_sym])
        .find_or_create_by!(name: add_on_name)
    end

    def seat_assignable?
      name.in?(SEAT_ASSIGNABLE_DUO_ADD_ONS)
    end
  end
end
