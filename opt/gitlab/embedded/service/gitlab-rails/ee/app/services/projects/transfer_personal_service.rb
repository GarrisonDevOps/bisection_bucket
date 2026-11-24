# frozen_string_literal: true

module Projects
  class TransferPersonalService < BaseService
    include Gitlab::Utils::StrongMemoize

    def execute
      path = ::Namespace.clean_path(project.namespace.path)

      response = Groups::CreateService.new(current_user, {
        name: path,
        path: path,
        organization_id: params[:organization_id]
      }).execute

      return ServiceResponse.error(message: response[:group].errors.full_messages.to_sentence) if response.error?

      if ::Projects::TransferService.new(project, current_user).execute(response[:group])
        ServiceResponse.success
      else
        ServiceResponse.error(message: 'Personal project cannot be transferred')
      end
    end
  end
end
