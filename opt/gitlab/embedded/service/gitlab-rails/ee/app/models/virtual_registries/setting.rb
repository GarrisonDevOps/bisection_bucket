# frozen_string_literal: true

module VirtualRegistries
  class Setting < ApplicationRecord
    belongs_to :group

    validates :group, top_level_group: true, presence: true, uniqueness: true
    validates :enabled, inclusion: { in: [true, false] }

    scope :enabled, -> { where(enabled: true) }

    def self.enabled_for_group?(group)
      Gitlab::SafeRequestStore.fetch([:virtual_registry_setting_enabled, group.id]) do
        find_for_group(group).enabled
      end
    end

    def self.find_for_group(group)
      find_or_initialize_by(group: group)
    end

    def self.declarative_policy_class
      'VirtualRegistries::Policies::GroupPolicy'
    end
  end
end
