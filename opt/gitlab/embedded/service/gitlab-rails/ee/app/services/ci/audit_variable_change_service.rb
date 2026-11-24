# frozen_string_literal: true

module Ci
  class AuditVariableChangeService < ::BaseContainerService
    include ::AuditEvents::Changes

    AUDITABLE_VARIABLE_CLASSES = [::Ci::Variable, ::Ci::GroupVariable, ::Ci::InstanceVariable].freeze
    TEXT_COLUMNS = {
      key: 'name of key',
      value: 'value(hidden)'
    }.freeze

    SECURITY_COLUMNS = {
      protected: 'variable protection',
      masked: 'variable masking',
      environment_scope: 'environment scope'
    }.freeze

    def execute
      return unless container.feature_available?(:audit_events)
      return unless AUDITABLE_VARIABLE_CLASSES.include? params[:variable].class

      case params[:action]
      when :create, :destroy
        log_audit_event(params[:action], params[:variable])
      when :update
        audit_update(params[:variable])
      end
    end

    private

    def audit_update(variable)
      SECURITY_COLUMNS.each do |column, as_text|
        audit_changes(
          column,
          as: as_text,
          entity: container,
          model: variable,
          target_details: variable.key,
          event_type: event_type_name(variable, :update)
        )
      end

      TEXT_COLUMNS.each do |column, as_text|
        audit_changes(
          column,
          as: as_text,
          entity: container,
          model: variable,
          target_details: variable.key,
          event_type: event_type_name(variable, :update),
          skip_changes: (column == :value)
        )
      end
    end

    def log_audit_event(action, variable)
      event_name = event_type_name(variable, action)

      audit_context = {
        name: event_name,
        author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new,
        scope: container,
        target: variable,
        message: message(variable, action),
        additional_details: build_additional_details(variable, action).merge({ event_name: event_name })
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    def event_type_name(variable, action)
      name = ci_variable_name(variable)
      case action
      when :create
        "#{name}_created"
      when :destroy
        "#{name}_deleted"
      when :update
        "#{name}_updated"
      end
    end

    def message(variable, action)
      name = ci_variable_name(variable).humanize(capitalize: false)
      case action
      when :create
        "Added #{name}"
      when :destroy
        "Removed #{name}"
      end
    end

    def build_additional_details(variable, action)
      name = ci_variable_name(variable)
      case action
      when :create
        { add: name }
      when :destroy
        { remove: name }
      end
    end

    def ci_variable_name(variable)
      variable.class.to_s.parameterize(preserve_case: true).underscore
    end
  end
end
