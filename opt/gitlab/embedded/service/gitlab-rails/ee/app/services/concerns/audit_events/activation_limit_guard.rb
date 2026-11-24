# frozen_string_literal: true

module AuditEvents
  module ActivationLimitGuard
    extend ActiveSupport::Concern

    private

    def validate_activation_limit(destination, active_value)
      return unless active_value == true && !destination.active? &&
        destination.class.respond_to?(:limit_relation)

      active_count, limits = if destination.class.limit_scope == Limitable::GLOBAL_SCOPE
                               [destination.class.active.count,
                                 ::GitlabSubscriptions::SystemDefined::Plan.default.actual_limits]
                             else
                               scope_relation = destination.public_send(destination.class.limit_scope) # rubocop:disable GitlabSecurity/PublicSend -- Need value from Limitable
                               return unless scope_relation

                               [destination.class.active_for_scope(scope_relation).count, scope_relation.actual_limits]
                             end

      limit_name = destination.class.limit_name
      limit_value = limits&.public_send(limit_name) # rubocop:disable GitlabSecurity/PublicSend -- Need value from Limitable

      return unless limit_value && active_count >= limit_value

      {
        error: format(
          _("Cannot activate: Maximum number of %{name} (%{count}) exceeded"),
          name: limit_name.to_s.humanize(capitalize: false),
          count: limit_value
        )
      }
    end

    def validate_activation_limit_for_update(destination, active_value)
      return unless active_value.present?

      limit_error = validate_activation_limit(destination, active_value)
      return limit_error[:error] if limit_error

      nil
    end
  end
end
