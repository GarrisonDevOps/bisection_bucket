# frozen_string_literal: true

module Notifications
  class TargetedMessageNamespace < ApplicationRecord
    belongs_to :targeted_message, optional: false
    belongs_to :namespace, optional: false
    has_many :targeted_message_dismissals

    validates_uniqueness_of :namespace_id, scope: :targeted_message_id

    scope :by_namespace_for_user, ->(ns, user) do
      join_sql = Notifications::TargetedMessageNamespace.sanitize_sql_array(["LEFT JOIN targeted_message_dismissals " \
        "ON targeted_message_namespaces.namespace_id = targeted_message_dismissals.namespace_id " \
        "AND targeted_message_namespaces.targeted_message_id = targeted_message_dismissals.targeted_message_id " \
        "AND targeted_message_dismissals.user_id = ?", user.id])

      Notifications::TargetedMessageNamespace.where(namespace: ns)
        .joins(join_sql)
        .where(targeted_message_dismissals: { id: nil })
    end

    scope :for_namespaces, ->(namespace_ids) { where(namespace_id: namespace_ids) }
  end
end
