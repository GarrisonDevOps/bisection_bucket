# frozen_string_literal: true

module Security
  module ScanProfiles
    class CreateScanProfileService
      AUDIT_EVENT_NAME = 'security_scan_profile_create'

      def initialize(namespace, params, current_user)
        @namespace = namespace
        @params = params
        @current_user = current_user
      end

      def execute
        return blank_triggers_error if Array(params[:triggers]).blank?

        profile = create_profile!
        audit_creation(profile)

        ServiceResponse.success(payload: { scan_profile: profile })
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages.to_sentence, reason: :invalid)
      end

      private

      attr_reader :namespace, :params, :current_user

      def blank_triggers_error
        ServiceResponse.error(message: 'A scan profile must have at least one trigger.', reason: :invalid)
      end

      def create_profile!
        Security::ScanProfile.transaction do
          profile = Security::ScanProfile.create!(
            namespace: namespace,
            scan_type: params[:scan_type],
            name: params[:name],
            description: params[:description]
          )

          Array(params[:triggers]).each do |trigger_params|
            create_trigger!(profile, trigger_params)
          end

          profile
        end
      end

      def create_trigger!(profile, trigger_params)
        profile.scan_profile_triggers.create!(
          namespace: profile.namespace,
          trigger_type: trigger_params[:trigger_type],
          configuration: build_configuration(profile, trigger_params)
        )
      end

      def build_configuration(profile, trigger_params)
        trigger_type = trigger_params[:trigger_type]
        values = configuration_values(profile, trigger_params[:configuration], trigger_type)
        return if values.blank?

        Security::ScanProfiles::Configuration.create!(
          scan_profile: profile,
          namespace: profile.namespace,
          configuration: values,
          trigger_type: trigger_type
        )
      end

      def configuration_values(profile, config_input, trigger_type)
        return if config_input.blank?
        return config_input unless params[:strip_defaults]

        Security::ScanProfiles::Configuration.strip_defaults(
          config_input, Security::ScanProfiles::Configuration.defaults_for(profile.scan_type, trigger_type)
        )
      end

      def audit_creation(profile)
        return if current_user.blank?

        ::Gitlab::Audit::Auditor.audit(
          name: AUDIT_EVENT_NAME,
          author: current_user,
          scope: profile.namespace,
          target: profile,
          message: "Created security scan profile '#{profile.name}'",
          additional_details: {
            organization_id: profile.namespace.organization_id,
            profile_id: profile.id,
            scan_type: profile.scan_type,
            trigger_types: profile.scan_profile_triggers.map(&:trigger_type)
          }
        )
      end
    end
  end
end
