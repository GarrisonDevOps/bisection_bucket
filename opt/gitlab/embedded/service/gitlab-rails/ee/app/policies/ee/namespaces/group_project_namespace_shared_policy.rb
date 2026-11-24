# frozen_string_literal: true

module EE
  module Namespaces
    module GroupProjectNamespaceSharedPolicy
      extend ActiveSupport::Concern

      prepended do
        with_scope :subject
        condition(:okrs_enabled) do
          @subject.okrs_mvc_feature_flag_enabled? && @subject.licensed_feature_available?(:okrs)
        end

        # at group level align group level work item permission with epic creation permission
        rule { can?(:create_epic) }.policy do
          enable :create_issue
          enable :create_work_item
        end

        rule { can?(:create_work_item) & okrs_enabled }.policy do
          enable :create_objective
          enable :create_key_result
        end

        rule { can?(:create_work_item) }.enable :create_task
      end
    end
  end
end
