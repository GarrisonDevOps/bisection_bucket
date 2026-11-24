# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ComplianceRequirementsControl < ApplicationRecord
      include Gitlab::EncryptedAttribute

      self.table_name = 'compliance_requirements_controls'
      attr_encrypted :secret_token,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false

      MAX_COMPLIANCE_CONTROLS_PER_REQUIREMENT_COUNT = 5
      CONTROL_EXPRESSION_SCHEMA_PATH = 'ee/app/validators/json_schemas/compliance_requirements_control_expression.json'
      CONTROL_EXPRESSION_SCHEMA = JSONSchemer.schema(Rails.root.join(CONTROL_EXPRESSION_SCHEMA_PATH))

      belongs_to :compliance_requirement,
        class_name: 'ComplianceManagement::ComplianceFramework::ComplianceRequirement',
        inverse_of: :compliance_requirements_controls, optional: false
      belongs_to :namespace

      has_many :project_control_compliance_statuses,
        class_name: 'ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus'

      has_many :project_compliance_violations, class_name: 'ComplianceManagement::Projects::ComplianceViolation'

      enum :name, ComplianceManagement::ComplianceFramework::Controls::Registry.enum_definitions

      enum :control_type, {
        internal: 0,
        external: 1
      }

      before_validation :set_predefined_expression, if: :internal?

      validates_presence_of :name, :control_type, :namespace, :compliance_requirement
      validates_presence_of :expression, if: :internal?

      validates :expression, length: { maximum: 255 }
      validate :validate_predefined_control, if: :internal?
      validate :validate_expression_schema, if: :internal?
      validate :controls_count_per_requirement
      validate :validate_expression_matches_control, if: :internal?

      validates :external_url, presence: true,
        # needs to evaluate .com? at runtime for specs to be able to differentiate - there must be a better way
        addressable_url: { allow_localhost: ->(record) { !record.saas? } },
        uniqueness: { scope: :compliance_requirement_id },
        if: :external?
      validates :name, uniqueness: { scope: :compliance_requirement_id }, if: :internal?
      validates :secret_token, presence: true, if: :external?
      validates :secret_token, length: { maximum: 240 }, allow_blank: true

      validates :external_control_name, length: { maximum: 255 }
      validates :external_control_name,
        uniqueness: { scope: :compliance_requirement_id },
        allow_blank: true,
        if: -> { external_control_name.present? }

      scope :for_framework, ->(framework_id) {
        joins(compliance_requirement: :framework)
          .where(compliance_management_frameworks: { id: framework_id })
      }

      scope :for_projects, ->(project_ids) {
        joins(compliance_requirement: { framework: :projects })
          .where(projects: { id: project_ids })
          .select('compliance_requirements_controls.*, projects.id as project_id')
      }

      def self.grouped_by_project(project_ids)
        for_projects(project_ids).group_by(&:project_id)
      end

      def expression_as_hash(symbolize_names: false)
        ::Gitlab::Json.parse(expression, symbolize_names: symbolize_names)
      rescue JSON::ParserError
        errors.add(:expression, _('should be a valid json object.'))

        nil
      end

      def saas?
        ::Gitlab::Saas.feature_available? :gitlab_com_subscriptions
      end

      private

      def predefined_control
        ComplianceManagement::ControlExpression.find(name.to_s)
      end

      def validate_predefined_control
        return if name.blank? || predefined_control

        errors.add(:name, _('is not a predefined compliance control.'))
      end

      def set_predefined_expression
        return if expression.present?

        control = predefined_control
        return if control.nil?

        self.expression = ::Gitlab::Json.dump(control.expression)
      end

      def controls_count_per_requirement
        return if compliance_requirement.nil?

        other_controls_count = compliance_requirement.compliance_requirements_controls.excluding(self).count
        return if other_controls_count < MAX_COMPLIANCE_CONTROLS_PER_REQUIREMENT_COUNT

        errors.add(:compliance_requirement, format(_("cannot have more than %{count} controls"),
          count: MAX_COMPLIANCE_CONTROLS_PER_REQUIREMENT_COUNT))
      end

      def validate_expression_schema
        return if expression.blank?

        hashed_expression = expression_as_hash
        return if errors[:expression].any?

        expression_schema_errors = CONTROL_EXPRESSION_SCHEMA.validate(hashed_expression).to_a
        return if expression_schema_errors.blank?

        expression_schema_errors.each do |error|
          errors.add(:expression, JSONSchemer::Errors.pretty(error))
        end
      end

      def validate_expression_matches_control
        return if errors[:expression].any? || expression.blank?

        hashed_expression = expression_as_hash(symbolize_names: true)
        return if errors[:expression].any?

        control = predefined_control
        return if control.nil? || control.matches_expression?(hashed_expression)

        errors.add(:expression, _("does not match the name of the predefined control."))
      end
    end
  end
end
