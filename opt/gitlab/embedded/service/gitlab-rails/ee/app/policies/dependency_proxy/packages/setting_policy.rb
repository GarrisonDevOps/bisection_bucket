# frozen_string_literal: true

module DependencyProxy
  module Packages
    class SettingPolicy < BasePolicy
      delegate(:project) { @subject.project }

      rule { ~can?(:_read_dependency_proxy_package) }.policy do
        prevent :read_package
      end
    end
  end
end
