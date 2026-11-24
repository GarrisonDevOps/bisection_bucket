# frozen_string_literal: true

module EE
  module ContainerRegistry
    module Protection
      module Concerns
        module TagRule
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          override :protected_for_delete?
          def protected_for_delete?(project:, current_user:)
            if project.licensed_feature_available?(:container_registry_immutable_tag_rules) &&
                project.container_registry_protection_tag_rules.immutable.exists? &&
                project.has_container_registry_tags?
              return true
            end

            super
          end

          override :user_can_admin_all_resources?
          def user_can_admin_all_resources?(user, project)
            immutable_tags_feature_available?(project) ? false : super
          end

          override :fetch_eligible_tag_rules_for_project
          def fetch_eligible_tag_rules_for_project(tag_rules, project, user)
            return super unless immutable_tags_feature_available?(project)

            # admins are only restricted by immutable tag rules
            return tag_rules.immutable if user&.can_admin_all_resources?

            tag_rules
          end

          def immutable_tags_feature_available?(project)
            project.licensed_feature_available?(:container_registry_immutable_tag_rules)
          end
        end
      end
    end
  end
end
