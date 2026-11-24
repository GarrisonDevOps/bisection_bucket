# frozen_string_literal: true

module EE
  module AbilityPrepend
    extend ActiveSupport::Concern

    class_methods do
      def users_that_can_read_project(users, project)
        ActiveRecord::Associations::Preloader.new(records: users, associations: :namespace_bans).call
        super
      end
    end
  end
end
