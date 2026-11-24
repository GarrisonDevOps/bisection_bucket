# frozen_string_literal: true

module GitlabSubscriptions
  module SystemDefined
    class AddOn
      include ActiveRecord::FixedItemsModel::Model

      # id must equal the value stored in subscription_add_on_purchases.subscription_add_on_uid
      # (the AR enum value of GitlabSubscriptions::AddOn#name).
      ITEMS = [
        {
          id: 1,
          name: 'code_suggestions',
          description: 'Add-on for GitLab Duo Pro.'
        },
        # 2 was product_analytics, removed in 19.4
        {
          id: 3,
          name: 'duo_enterprise',
          description: 'Add-on for GitLab Duo Enterprise.'
        },
        {
          id: 4,
          name: 'duo_amazon_q',
          description: 'Add-on for GitLab Duo with Amazon Q.'
        },
        {
          id: 5,
          name: 'duo_core',
          description: 'Add-on for GitLab Duo Core.'
        },
        {
          id: 6,
          name: 'self_hosted_dap',
          description: 'Add-on for GitLab Duo Agent Platform Self-Hosted.'
        },
        {
          id: 7,
          name: 'gitlab_credits',
          description: 'Add-on for GitLab Credits.'
        },
        {
          id: 8,
          name: 'secrets_manager',
          description: 'Add-on for GitLab Secrets Manager.'
        },
        {
          id: 9,
          name: 'flex_offline',
          description: 'Add-on for GitLab Flex Offline.'
        },
        {
          id: 10,
          name: 'orbit_promo',
          description: 'Add-on for GitLab Orbit Promotional ELA.'
        }
      ].freeze

      DUO_ADD_ONS = %i[code_suggestions duo_enterprise duo_amazon_q duo_core self_hosted_dap gitlab_credits].freeze
      SEAT_ASSIGNABLE_DUO_ADD_ONS = %w[code_suggestions duo_enterprise].freeze

      attribute :name, :string
      attribute :description, :string

      validates :name, :description, presence: true

      ITEMS.each do |item|
        define_method(:"#{item[:name]}?") { name == item[:name] }
      end

      class << self
        def names
          @names ||= all.to_h { |item| [item.name, item.id] }.with_indifferent_access
        end

        def uids_for_names(add_on_names)
          hash = names

          Array.wrap(add_on_names).filter_map { |name| hash[name.to_s] }
        end

        def names_for_uids(uids)
          where(id: uids).map(&:name)
        end

        def name_for_uid(uid)
          find_by(id: uid)&.name
        end
      end

      def seat_assignable?
        name.in?(SEAT_ASSIGNABLE_DUO_ADD_ONS)
      end
    end
  end
end
