# frozen_string_literal: true

module EE
  module Gitlab
    module ImportExport
      module Project
        module RelationFactory
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          EE_OVERRIDES = {
            deploy_access_levels: 'ProtectedEnvironments::DeployAccessLevel',
            unprotect_access_levels: 'ProtectedBranch::UnprotectAccessLevel',
            security_setting: 'ProjectSecuritySetting',
            iterations_cadence: 'Iterations::Cadence',
            approval_rules: 'ApprovalProjectRule',
            approval_project_rules_users: 'ApprovalProjectRulesUser',
            approval_project_rules_protected_branches: 'ApprovalProjectRulesProtectedBranch',
            findings: 'Vulnerabilities::Finding',
            vulnerability_finding: 'Vulnerabilities::Finding',
            scanner: 'Vulnerabilities::Scanner',
            primary_identifier: 'Vulnerabilities::Identifier',
            identifiers: 'Vulnerabilities::Identifier',
            initial_finding_pipeline: 'Ci::Pipeline',
            latest_finding_pipeline: 'Ci::Pipeline',
            vulnerability_read: 'Vulnerabilities::Read'
          }.freeze

          EE_EXISTING_OBJECT_RELATIONS = %i[
            iteration
            iterations_cadence
            push_rule
            Vulnerabilities::Scanner
            Vulnerabilities::Identifier
            initial_finding_pipeline
            latest_finding_pipeline
          ].freeze

          PROTECTED_ACCESS_LEVEL_RELATION_NAMES = %i[
            ProtectedBranch::MergeAccessLevel
            ProtectedBranch::PushAccessLevel
            ProtectedBranch::UnprotectAccessLevel
            ProtectedTag::CreateAccessLevel
          ].freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :overrides
            def overrides
              super.merge(EE_OVERRIDES)
            end

            override :existing_object_relations
            def existing_object_relations
              super + EE_EXISTING_OBJECT_RELATIONS
            end
          end

          override :invalid_relation?
          def invalid_relation?
            super || iteration_relation_without_group? || protected_access_level?
          end

          override :setup_models
          def setup_models
            case relation_name
            when :"Vulnerabilities::Finding" then setup_vulnerability_finding
            when :vulnerabilities then setup_vulnerability
            end
            super
          end

          # ProtectedBranch merge and push access levels cannot be assigned to
          # users without project administration permissions as they may gain
          # access to sensitive data like group CI/CD variables.
          def protected_access_level?
            user_access_level_relation? && !user_can_admin_importable?
          end

          def user_access_level_relation?
            relation_name.in?(PROTECTED_ACCESS_LEVEL_RELATION_NAMES) &&
              relation_hash['user_id'].present?
          end

          def user_can_admin_importable?
            user.can_admin_all_resources? || Ability.allowed?(user, :grant_protected_ref_access, importable)
          end

          override :generate_imported_object
          def generate_imported_object
            imported_object = super

            return if iteration_event_without_iteration?(imported_object)

            log_iteration_not_found if relation_name == :iteration && imported_object.nil?

            imported_object
          end

          def setup_vulnerability_finding
            relation_hash['uuid'] = ::Security::VulnerabilityUUID.generate(
              report_type: relation_hash['report_type'],
              primary_identifier_fingerprint: relation_hash['primary_identifier_fingerprint'],
              location_fingerprint: relation_hash['location_fingerprint'],
              project_id: relation_hash['project_id'],
              tracked_context: nil
            )
          end

          def setup_vulnerability
            relation_hash['vulnerability_finding'].save!
            relation_hash['findings'] = [relation_hash['vulnerability_finding']]
          end

          # Skip creation of iteration related relations if a project is not imported into a group,
          # as iterations are currently not allowed to be created in a project
          def iteration_relation_without_group?
            %i[resource_iteration_events iteration Iterations::Cadence].include?(relation_name) && importable.group.nil?
          end

          def log_iteration_not_found
            ::Import::Framework::Logger.warn(
              message: '[Project/Group Import] Iteration not found, dropping iteration link',
              import_type: importable.import_type,
              Labkit::Fields::GL_PROJECT_ID => importable.id,
              relation_index: relation_index,
              iteration_iid: relation_hash['iid'],
              iteration_start_date: relation_hash['start_date'],
              iteration_due_date: relation_hash['due_date']
            )
          end

          def iteration_event_without_iteration?(object)
            relation_name == :resource_iteration_events && object&.iteration.nil?
          end
        end
      end
    end
  end
end
