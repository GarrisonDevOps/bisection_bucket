# frozen_string_literal: true

module Terraform
  module States
    class DestroyWorker
      include ApplicationWorker

      queue_namespace :terraform
      feature_category :infrastructure_as_code

      deduplicate :until_executed
      idempotent!
      urgency :low
      data_consistency :always

      def perform(terraform_state_id, params = {})
        state = Terraform::State.find_by_id(terraform_state_id)
        return unless state

        user = User.find_by_id(params['user_id']) if params['user_id']

        Terraform::States::DestroyService.new(state, permanent: params['permanent'], current_user: user).execute
      end
    end
  end
end
