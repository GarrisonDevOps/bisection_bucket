# frozen_string_literal: true

module Users
  class BuildBotService < ::Users::AuthorizedBuildService
    extend ::Gitlab::Utils::Override

    private

    override :signup_params
    def signup_params
      super << :private_profile
    end
  end
end
