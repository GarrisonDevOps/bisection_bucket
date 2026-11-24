# frozen_string_literal: true

module EE
  module AwardEmoji # rubocop:disable Gitlab/BoundedContexts -- Overrides an existing class. If nothing else is added it can be deleted after epic to work items migration.
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      before_validation :rewrite_epic_awardable_type, on: :create
    end

    private

    def rewrite_epic_awardable_type
      return unless awardable
      return unless awardable_type == 'Epic'

      self.awardable_id = awardable.issue_id
      self.awardable_type = 'Issue'
    end

    override :ensure_sharding_key
    def ensure_sharding_key
      return if [namespace, organization].any?(&:present?)

      case awardable
      when Epic
        self.namespace_id = awardable.group_id
        self.organization_id = nil
      else
        super
      end
    end
  end
end
