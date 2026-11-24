# frozen_string_literal: true

module ComplianceManagement
  module Projects
    class ComplianceViolation < ApplicationRecord
      include ::Noteable
      include ::Todoable
      include ::Mentionable
      include ::Awardable

      self.table_name = 'project_compliance_violations'

      belongs_to :project
      belongs_to :namespace
      belongs_to :compliance_control,
        class_name: 'ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl',
        foreign_key: 'compliance_requirements_control_id', inverse_of: :project_compliance_violations
      has_many :compliance_violation_issues, class_name: 'ComplianceManagement::Projects::ComplianceViolationIssue',
        foreign_key: 'project_compliance_violation_id', inverse_of: :project_compliance_violation
      has_many :issues, through: :compliance_violation_issues
      has_many :notes, as: :noteable

      validates_presence_of :project, :namespace, :compliance_control, :status, :audit_event_table_name

      validates :audit_event_id,
        uniqueness: { scope: :compliance_requirements_control_id,
                      message: ->(_object, _data) {
                        _('has already been recorded as a violation for this compliance control')
                      } }

      # Validate associations for data consistency
      validate :project_belongs_to_namespace
      validate :compliance_control_belongs_to_namespace
      validate :audit_event_has_valid_entity_association
      validate :validate_audit_event_presence

      attribute :status, :integer, limit: 2
      enum :status, ::Enums::ComplianceManagement::Projects::ComplianceViolation.status

      attribute :audit_event_table_name, :integer, limit: 2
      enum :audit_event_table_name, {
        project_audit_events: 0,
        group_audit_events: 1,
        user_audit_events: 2,
        instance_audit_events: 3
      }

      scope :order_by_created_at_and_id, ->(direction = :asc) { order(created_at: direction, id: direction) }

      scope :in_optimization_array_mapping_scope, ->(id_expression) {
        where(arel_table[:namespace_id].eq(id_expression))
      }
      scope :in_optimization_finder_query, ->(_project_id_expression, id_expression) {
        where(arel_table[:id].eq(id_expression))
      }
      scope :for_projects, ->(project_ids) { where(project_id: project_ids) }
      scope :for_controls, ->(control_ids) { where(compliance_requirements_control_id: control_ids) }
      scope :for_status, ->(status) { where(status: status) }
      scope :created_on_or_before, ->(date) { where(created_at: ..date.end_of_day) }
      scope :created_on_or_after, ->(date) { where(created_at: date.beginning_of_day..) }

      scope :including_controls, -> {
        includes(:compliance_control, compliance_control: { compliance_requirement: :framework })
      }

      def audit_event
        @audit_event ||= audit_event_class&.find_by(id: audit_event_id)
      end

      # Used by app/policies/todo_policy.rb
      def readable_by?(user)
        Ability.allowed?(user, :read_compliance_violations_report, self)
      end

      def name
        "Compliance Violation ##{id}"
      end

      def framework
        requirement&.framework
      end

      def requirement
        compliance_control&.compliance_requirement
      end

      def to_global_id(_options = {})
        ::Gitlab::GlobalId.as_global_id(id, model_name: self.class.name)
      end

      def to_ability_name
        'compliance_violations_report'
      end

      private

      def audit_event_class
        case audit_event_table_name
        when 'project_audit_events' then ::AuditEvents::ProjectAuditEvent
        when 'group_audit_events' then ::AuditEvents::GroupAuditEvent
        when 'user_audit_events' then ::AuditEvents::UserAuditEvent
        when 'instance_audit_events' then ::AuditEvents::InstanceAuditEvent
        end
      end

      def project_belongs_to_namespace
        return unless project && namespace_id

        if project.namespace_id != namespace_id # rubocop:disable Style/GuardClause -- Easier to read
          errors.add(:project, _('must belong to the specified namespace'))
        end
      end

      def compliance_control_belongs_to_namespace
        return unless compliance_control && project

        if compliance_control.namespace_id != project.root_namespace.id # rubocop:disable Style/GuardClause -- Easier to read
          errors.add(:compliance_control, _('must belong to the specified namespace'))
        end
      end

      def validate_audit_event_presence
        return if audit_event_id.blank? || audit_event_table_name.blank?

        return if audit_event

        table_name = audit_event_table_name.humanize.downcase
        errors.add(:audit_event_id, format(_("does not exist in %{table_name}"), table_name: table_name))
      end

      def audit_event_has_valid_entity_association
        return unless audit_event

        entity = audit_event.entity

        return if entity.is_a?(::Gitlab::Audit::NullEntity)

        case audit_event.entity_type
        when 'Project'
          if project_id && audit_event.entity_id != project_id
            errors.add(:audit_event_id, _('must reference the specified project as its entity'))
          end
        when 'Group'
          if namespace && namespace.self_and_ancestor_ids.exclude?(audit_event.entity_id)
            errors.add(:audit_event_id, _('must reference the specified namespace as its entity'))
          end
        else
          errors.add(:audit_event_id, _('must be associated with either a Project or Group entity type'))
        end
      end
    end
  end
end
