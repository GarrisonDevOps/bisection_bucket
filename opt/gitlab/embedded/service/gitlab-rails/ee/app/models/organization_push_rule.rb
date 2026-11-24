# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts, Gitlab/NamespacedClass -- Will be decided on after https://gitlab.com/groups/gitlab-org/-/epics/16894 is finalized
class OrganizationPushRule < ApplicationRecord
  include PushRuleable

  belongs_to :organization, class_name: 'Organizations::Organization', optional: false

  def available?(feature_sym, **)
    License.feature_available?(feature_sym)
  end
end
# rubocop:enable Gitlab/BoundedContexts, Gitlab/NamespacedClass -- Will be decided on after https://gitlab.com/groups/gitlab-org/-/epics/16894 is finalized
