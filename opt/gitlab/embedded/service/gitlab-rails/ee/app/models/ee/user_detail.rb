# frozen_string_literal: true

module EE
  module UserDetail
    extend ActiveSupport::Concern

    prepended do
      belongs_to :enterprise_group, class_name: 'Group', optional: true, inverse_of: :enterprise_user_details

      scope :with_enterprise_group, -> { where.not(enterprise_group_id: nil) }

      attribute :onboarding_status, ::Gitlab::Database::Type::IndifferentJsonb.new
      store_accessor(
        :onboarding_status, :step_url, :email_opt_in, :initial_registration_type,
        :registration_type, :registration_objective, :setup_for_company,
        :glm_content, :glm_source, :joining_project, :role, :country, prefix: true
      )

      def self.onboarding_status_registration_objectives
        {
          'basics' => 0,
          'move_repository' => 1,
          'code_storage' => 2,
          'exploring' => 3,
          'ci' => 4,
          'other' => 5,
          'joining_team' => 6
        }
      end

      # Values here should match the role enums in app/validators/json_schemas/user_detail_onboarding_status.json
      def self.onboarding_status_roles
        {
          'software_developer' => 0,
          'development_team_lead' => 1,
          'devops_engineer' => 2,
          'systems_administrator' => 3,
          'security_analyst' => 4,
          'data_analyst' => 5,
          'product_manager' => 6,
          'product_designer' => 7,
          'other' => 8
        }
      end

      def onboarding_status_role_name
        self.class.onboarding_status_roles.key(onboarding_status_role)
      end

      def onboarding_status_role=(value)
        if value.present?
          int_value = value.is_a?(String) ? value.to_i : value
          super(int_value)
        else
          super(nil)
        end
      end

      def onboarding_status_registration_objective_name
        self.class.onboarding_status_registration_objectives.key(onboarding_status_registration_objective)
      end

      def onboarding_status_registration_objective=(value)
        if value.present?
          int_value = value.is_a?(String) ? value.to_i : value
          super(int_value)
        else
          super(nil)
        end
      end

      def onboarding_status_joining_project=(value)
        super(::Gitlab::Utils.to_boolean(value, default: false))
      end

      def onboarding_status_setup_for_company=(value)
        super(::Gitlab::Utils.to_boolean(value, default: false))
      end

      def onboarding_status_email_opt_in=(value)
        super(::Gitlab::Utils.to_boolean(value, default: false))
      end
    end
  end
end
