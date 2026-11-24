# frozen_string_literal: true

module EE
  module API
    module Entities
      module Group
        extend ActiveSupport::Concern

        prepended do
          expose :ldap_cn, :ldap_access
          expose :ldap_group_links,
            using: ::API::Entities::LdapGroupLink,
            if: ->(group, options) { group.ldap_group_links.any? }, documentation: { is_array: true }

          expose :saml_group_links,
            using: ::API::Entities::SamlGroupLink,
            if: ->(group, options) { group.saml_group_links.any? }, documentation: { is_array: true }

          expose :checked_file_template_project_id,
            as: :file_template_project_id,
            if: ->(group, options) {
              group.licensed_feature_available?(:custom_file_templates_for_namespace) &&
                Ability.allowed?(options[:current_user], :read_project, group.checked_file_template_project)
            }

          expose :wiki_access_level do |group|
            group.group_feature.string_access_level(:wiki)
          end

          expose :repository_storage,
            if: ->(group, options) {
              group.licensed_feature_available?(:group_wikis) &&
                Ability.allowed?(options[:current_user], :change_repository_storage)
            } do |group|
            group.group_wiki_repository&.shard_name
          end

          expose :duo_core_features_enabled,
            if: ->(group, options) {
              group.licensed_duo_core_features_available? &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            }, documentation: {
              desc: '[Experimental] Indicates whether GitLab Duo Core features are enabled for the group',
              type: 'Boolean'
            }

          expose :duo_features_enabled,
            if: ->(group, options) {
              group.licensed_ai_features_available? &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            }, documentation: {
              type: 'Boolean',
              desc: 'If `true`, GitLab Duo features are enabled for the group. Premium and Ultimate only.'
            }
          expose :lock_duo_features_enabled,
            if: ->(group, options) {
              group.licensed_ai_features_available? &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            }, documentation: {
              type: 'Boolean',
              desc: 'If `true`, the GitLab Duo features enabled setting is enforced for all ' \
                'subgroups. Premium and Ultimate only.'
            }
          expose :auto_duo_code_review_enabled,
            if: ->(group, options) {
              ::Gitlab::Duo::CodeReview.automatic_review_available?(group) &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            }
          with_options if: ->(group, options) {
            Ability.allowed?(options[:current_user], :admin_group, group) &&
              ::Gitlab::Duo::CodeReview.depth_settings_available?(group)
          } do
            expose :duo_code_review_depth_allowed, documentation: { type: 'Boolean' }
            expose :duo_code_review_default_depth, documentation: { type: 'String', example: 'lite' }
          end
          expose :duo_code_review_decisions_enabled,
            if: ->(group, options) {
              ::Gitlab::Duo::CodeReview.decisions_settings_available?(group) &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            }
          expose :web_based_commit_signing_enabled,
            if: ->(group, options) {
              ::Gitlab::Saas.feature_available?(:repositories_web_based_commit_signing) &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            }
          expose :allow_personal_snippets,
            if: ->(group, options) {
              group.allow_personal_snippets_available?(options[:current_user])
            }
          expose :duo_namespace_access_rules,
            if: ->(group, options) {
              group.root? &&
                Ability.allowed?(options[:current_user], :admin_group, group)
            } do |group|
            namespace_feature_access_rules(group.ai_feature_rules.group_by_through_namespace)
          end

          can_admin_built_in_templates_enabled = ->(group, options) {
            group.built_in_project_templates_enabled_available? &&
              Ability.allowed?(options[:current_user], :admin_group, group)
          }

          expose :built_in_project_templates_enabled,
            if: can_admin_built_in_templates_enabled,
            documentation: { type: 'Boolean' }
          expose :lock_built_in_project_templates_enabled,
            if: can_admin_built_in_templates_enabled,
            documentation: { type: 'Boolean' }
        end

        private

        def namespace_feature_access_rules(rules)
          ::Ai::FeatureAccessRuleTransformer.transform(rules)
        end
      end
    end
  end
end
