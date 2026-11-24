# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PolicyCommitService < ::BaseContainerService
      include Gitlab::Loggable
      include ::Gitlab::InternalEventsTracking

      def execute
        @policy_configuration = container.security_orchestration_policy_configuration

        return error('Security Policy Project does not exist') unless policy_configuration.present?

        validation_result = validate_policy_yaml
        return validation_result if validation_result[:status] != :success

        process_policy_result = process_policy
        return process_policy_result if process_policy_result[:status] != :success

        result = commit_policy(process_policy_result[:policy_hash])
        return error(result[:message], :bad_request) if result[:status] != :success

        success({ branch: branch_name })
      rescue StandardError => e
        error(e.message, :bad_request)
      end

      private

      def validate_policy_yaml
        validation_params = {
          policy: policy,
          operation: params[:operation]
        }

        Security::SecurityOrchestrationPolicies::ValidatePolicyService
          .new(container: container, current_user: current_user, params: validation_params)
          .execute
      end

      def process_policy
        ProcessPolicyService.new(
          policy_configuration: policy_configuration,
          params: {
            operation: params[:operation],
            name: params[:name],
            policy: policy,
            type: policy.delete(:type)&.to_sym
          }
        ).execute
      end

      def commit_policy(policy_hash)
        policy_yaml = YAML.dump(policy_hash.deep_stringify_keys)
        yaml_to_commit = annotate_policy_yaml(policy_yaml, policy_hash)

        current_yaml = policy_configuration.policy_blob
        if current_yaml.present?
          return error('No changes detected in the policy YAML') if current_yaml == yaml_to_commit

          return create_commit(::Files::UpdateService, yaml_to_commit)
        end

        create_commit(::Files::CreateService, yaml_to_commit)
      end

      def annotate_policy_yaml(policy_yaml, policy_hash)
        return policy_yaml unless policy_yaml_annotation_enabled?(policy_hash)

        response = SecurityOrchestrationPolicies::AnnotatePolicyYamlService.new(
          current_user, policy_yaml
        ).execute

        if response.success?
          log_successful_policy_yaml_annotation
          response[:annotated_yaml]
        else
          policy_yaml
        end
      end

      def policy_yaml_annotation_enabled?(policy_hash)
        policy_hash.dig(:experiments, :annotate_ids, :enabled) || false
      end

      def create_commit(service, policy_yaml)
        service.new(policy_configuration.security_policy_management_project, current_user, policy_commit_attrs(policy_yaml)).execute
      end

      def policy_commit_attrs(policy_yaml)
        {
          commit_message: commit_message,
          file_path: Security::OrchestrationPolicyConfiguration::POLICY_PATH,
          file_content: policy_yaml,
          branch_name: branch_name,
          start_branch: policy_configuration.default_branch_or_main
        }
      end

      def commit_message
        operation = case params[:operation]
                    when :append then 'Add a new policy to'
                    when :replace then 'Update policy in'
                    when :remove then 'Delete policy in'
                    end

        "#{operation} #{Security::OrchestrationPolicyConfiguration::POLICY_PATH}"
      end

      def log_successful_policy_yaml_annotation
        Gitlab::AppJsonLogger.info(
          build_structured_payload(
            security_orchestration_policy_configuration_id: policy_configuration.id,
            security_policy_management_project_id: policy_configuration.security_policy_management_project_id,
            operation: params[:operation],
            user_id: current_user.id,
            message: 'Successfully annotated policy YAML'
          )
        )

        track_internal_event('security_policy_yaml_annotated',
          user: current_user,
          project: policy_configuration.security_policy_management_project,
          additional_properties: {
            label: params[:operation].to_s
          }
        )
      end

      def branch_name
        @branch_name ||= params[:branch_name] || "update-policy-#{Time.now.to_i}"
      end

      def policy
        @policy ||= Gitlab::Config::Loader::Yaml.new(params[:policy_yaml]).load!
      end

      attr_reader :policy_configuration
    end
  end
end
