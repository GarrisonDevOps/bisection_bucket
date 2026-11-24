# frozen_string_literal: true

module EE
  module Projects
    module Settings
      module BranchRulesController
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        prepended do
          before_action do
            push_licensed_feature(:branch_rule_squash_options, @project)
          end
        end
      end
    end
  end
end
