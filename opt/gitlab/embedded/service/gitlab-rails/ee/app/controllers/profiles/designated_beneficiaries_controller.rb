# frozen_string_literal: true

module Profiles
  class DesignatedBeneficiariesController < Profiles::ApplicationController
    include SafeFormatHelper

    before_action :find_designated_beneficiary, only: [:update, :destroy]

    feature_category :user_profile

    def create
      @designated_beneficiary = current_user.designated_beneficiaries.build(create_params)

      if designated_beneficiary.save
        flash[:success] = create_update_success_message(designated_beneficiary, "added")
      else
        flash[:alert] = formatted_error_message(designated_beneficiary)
      end

      redirect_to profile_account_path
    end

    def update
      if designated_beneficiary.update(update_params)
        flash[:success] = create_update_success_message(designated_beneficiary, "updated")
      else
        flash[:alert] = formatted_error_message(designated_beneficiary)
      end

      redirect_to profile_account_path
    end

    def destroy
      type = designated_beneficiary.type

      if designated_beneficiary.destroy
        flash[:notice] = destroy_success_message(type)
      else
        # We don't expect to reach there unless we set up before_destroy callbacks or dependent associations.
        flash[:alert] = s_('Profiles|Failed to delete designated account beneficiary.')
      end

      redirect_to profile_account_path, status: :see_other
    end

    private

    attr_reader :designated_beneficiary

    def find_designated_beneficiary
      @designated_beneficiary = current_user.designated_beneficiaries.find(params.require(:id))
    rescue ActiveRecord::RecordNotFound # Handle concurrent deletions gracefully (e.g. two browser tabs)
      flash[:notice] = s_('Profiles|Designated account beneficiary already deleted.')
      redirect_to profile_account_path, status: :see_other
    end

    def create_params
      params.require(:users_designated_beneficiary).permit(:name, :email, :relationship, :type)
    end

    def update_params
      # Explicitly exclude :type from update params to prevent type changes
      params.require(:users_designated_beneficiary).permit(:name, :email, :relationship)
    end

    def destroy_success_message(type)
      format(s_('Profiles|Account %{type} deleted successfully.'), type: type)
    end

    def create_update_success_message(beneficiary, action)
      # rubocop:disable Layout/LineLength -- For readability of copy
      safe_format(
        s_('Profiles|Account %{type} %{action} successfully. They can %{link_start}contact GitLab%{link_end} to gain access to your account in the event of your %{event}.'),
        contact_gitlab_link_tag.merge(type: beneficiary.type, action: action, event: event_type_for(beneficiary))
      )
      # rubocop:enable Layout/LineLength
    end

    def contact_gitlab_url
      'https://about.gitlab.com/support/#contact-support'
    end

    def event_type_for(beneficiary)
      beneficiary.manager? ? s_('Profiles|incapacitation') : s_('Profiles|death')
    end

    def contact_gitlab_link_tag
      contact_link = helpers.link_to('', contact_gitlab_url, target: '_blank', rel: 'noopener noreferrer')
      tag_pair(contact_link, :link_start, :link_end)
    end

    def formatted_error_message(record)
      record.errors.messages.values.flatten.to_sentence
    end
  end
end
