# frozen_string_literal: true

module AuditEvents
  module Activatable
    extend ActiveSupport::Concern

    # The plan limit counts active rows only, so this caps total rows to stop create-deactivate loops.
    TOTAL_LIMIT = 50

    included do
      scope :active, -> { where(active: true) }
      scope :active_for_scope, ->(scope_relation) { active.where(limit_scope => scope_relation) }
      validate :validate_activation_limit_on_update
      validate :validate_total_limit, on: :create

      class_eval do
        self.limit_relation = :active_records_for_limit_check if respond_to?(:limit_relation=)
      end
    end

    def active?
      active
    end

    def activate!
      validate_activation_limit_for_method if self.class.respond_to?(:limit_relation) && !active?

      update!(active: true)
    end

    def deactivate!
      update!(active: false)
    end

    def active_records_for_limit_check
      if self.class.limit_scope == Limitable::GLOBAL_SCOPE
        self.class.active
      else
        scope_relation = public_send(self.class.limit_scope) # rubocop:disable GitlabSecurity/PublicSend -- Need to read from Limitable
        self.class.active_for_scope(scope_relation)
      end
    end

    private

    def validate_total_limit
      return if self.class.limit_scope == Limitable::GLOBAL_SCOPE

      scope_relation = public_send(self.class.limit_scope) # rubocop:disable GitlabSecurity/PublicSend -- Need to read from Limitable
      return unless scope_relation
      return unless total_limit_reached?(scope_relation)

      unless ::Feature.enabled?(:enforce_audit_streaming_destination_limits, scope_relation)
        ::Gitlab::AppJsonLogger.info(
          message: 'Audit streaming destination total limit exceeded',
          model: self.class.name,
          ::Labkit::Fields::GL_NAMESPACE_ID => scope_relation.id,
          limit: TOTAL_LIMIT
        )
        return
      end

      errors.add(:base,
        format(_("Maximum number of %{name} (%{count}) exceeded, including inactive ones. " \
          "Delete unused destinations to add more."),
          name: self.class.limit_name.humanize(capitalize: false), count: TOTAL_LIMIT))
    end

    def total_limit_reached?(scope_relation)
      relations = [self.class.where(self.class.limit_scope => scope_relation)]

      # Legacy API creates are copied into the streaming destinations table, the only one streaming reads.
      if is_a?(GroupStreamDestinationMappable) && stream_destination_id.nil?
        relations << scope_relation.external_audit_event_streaming_destinations
      end

      relations.any? { |relation| relation.limit(TOTAL_LIMIT).count >= TOTAL_LIMIT }
    end

    def will_be_activated?
      active_changed? && active? && !active_was
    end

    def validate_activation_limit_on_update
      return unless will_be_activated?

      validate_activation_limit_for_method
    rescue ActiveRecord::RecordInvalid
    end

    def validate_activation_limit_for_method
      return if active?
      return unless self.class.respond_to?(:limit_relation)

      if self.class.limit_scope == Limitable::GLOBAL_SCOPE
        current_active_count = self.class.active.count
        limits = ::GitlabSubscriptions::SystemDefined::Plan.default.actual_limits
      else
        scope_relation = public_send(self.class.limit_scope) # rubocop:disable GitlabSecurity/PublicSend -- Need to read from Limitable
        return unless scope_relation

        current_active_count = self.class.active_for_scope(scope_relation).count
        limits = scope_relation.actual_limits
      end

      limit_name = self.class.limit_name
      limit_value = limits&.public_send(limit_name) # rubocop:disable GitlabSecurity/PublicSend -- Need to read from Limitable

      return unless limit_value && current_active_count >= limit_value

      errors.add(:base,
        format(_("Cannot activate: Maximum number of %{name} (%{count}) exceeded"),
          name: limit_name.humanize(capitalize: false), count: limit_value))

      raise ActiveRecord::RecordInvalid, self
    end
  end
end
